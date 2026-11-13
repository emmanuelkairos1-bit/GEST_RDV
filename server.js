const express = require('express'), session = require('express-session'), mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs'), crypto = require('crypto'), path = require('path'), fs = require('fs');
const cfg = require('./config');
const STATUTS = ['En attente', 'Validé', 'Reporté', 'Refusé'];
const pool = mysql.createPool({ ...cfg.db, waitForConnections: true, connectionLimit: 10, charset: 'utf8mb4', dateStrings: true });
const rows = async (sql, p = []) => (await pool.execute(sql, p))[0];
const one = async (sql, p = []) => (await rows(sql, p))[0];

// ---------- SÉCURITÉ : clés, chiffrement, mots de passe, blocage ----------
const COST = 12, LOCK_MS = 2 * 3600 * 1000, MAX_FAILS = 3, MAX_IP_FAILS = 10;
function loadMasterKey() {
  const k = process.env.GEST_RDV_KEY || cfg.cleChiffrement;
  if (k) { if (!/^[0-9a-f]{64}$/i.test(k)) throw new Error('cleChiffrement : 64 caractères hexadécimaux attendus.'); return Buffer.from(k, 'hex'); }
  const f = path.join(__dirname, 'secret.key');
  if (fs.existsSync(f)) return Buffer.from(fs.readFileSync(f, 'utf8').trim(), 'hex');
  const b = crypto.randomBytes(32); fs.writeFileSync(f, b.toString('hex'), { mode: 0o600 });
  console.log('ATTENTION : clé de chiffrement créée dans secret.key. SAUVEGARDEZ-LA : sans elle, les données chiffrées sont perdues.');
  return b;
}
const MASTER = loadMasterKey();
const sub = i => Buffer.from(crypto.hkdfSync('sha256', MASTER, Buffer.alloc(0), i, 32));
const K_ENC = sub('gest_rdv-enc'), K_IDX = sub('gest_rdv-idx');
const SESSION_SECRET = cfg.secret && !/^CHANGEZ/.test(cfg.secret) ? cfg.secret : crypto.createHmac('sha256', MASTER).update('session').digest('hex');
// AES-256-GCM : chaque valeur a son IV aléatoire et son étiquette d'authenticité
const enc = v => { if (v == null) return null; const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', K_ENC, iv); const ct = Buffer.concat([c.update(String(v), 'utf8'), c.final()]); return 'v1:' + Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64'); };
const dec = v => { if (v == null) return null; v = String(v); if (!v.startsWith('v1:')) return v; try { const b = Buffer.from(v.slice(3), 'base64'), d = crypto.createDecipheriv('aes-256-gcm', K_ENC, b.subarray(0, 12)); d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'); } catch { return '[illisible : mauvaise clé]'; } };
const bidx = v => crypto.createHmac('sha256', K_IDX).update(String(v).trim().toLowerCase()).digest('hex'); // index aveugle (recherche exacte sans déchiffrer)
const decRdv = r => ({ ...r, nom: dec(r.nom), prenom: dec(r.prenom), telephone: dec(r.telephone), email: dec(r.email), motif: dec(r.motif), motif_report_refus: dec(r.motif_report_refus) });
const DUMMY_HASH = bcrypt.hashSync('Dummy#Password-1', COST);

const COMMON = ['password', 'motdepasse', 'azerty', 'qwerty', 'admin', 'bienvenue', 'welcome', 'letmein', 'iloveyou', 'soleil', 'senegal', 'dakar', 'abcdef', 'master', 'login', 'monkey', 'dragon', 'football', 'princesse', 'chocolat', 'changeme', 'secret', 'gestrdv', 'clinique', 'ecole', 'eglise', 'france', 'camerou', 'bonjour', 'azertyuiop'];
const SEQ = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'azertyuiop', 'qsdfghjklm', 'wxcvbn', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
const hasSeq = s => SEQ.some(q => { const r = [...q].reverse().join(''); for (let i = 0; i <= s.length - 4; i++) { const t = s.slice(i, i + 4); if (q.includes(t) || r.includes(t)) return true; } return false; });
function pwError(pw, ctx = []) {
  if (pw.length < 10) return 'Mot de passe trop court : 10 caractères minimum.';
  if (Buffer.byteLength(pw) > 72) return 'Mot de passe trop long : 72 octets maximum.';
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/\d/.test(pw) || !/[^A-Za-z0-9]/.test(pw)) return 'Mot de passe trop simple : il faut une minuscule, une majuscule, un chiffre et un symbole (! @ # $ % & * ? …).';
  const low = pw.toLowerCase(), norm = low.replace(/@/g, 'a').replace(/\$/g, 's').replace(/!/g, 'i').replace(/0/g, 'o').replace(/1/g, 'i').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't').replace(/[^a-z]/g, '');
  if (COMMON.some(w => norm.includes(w))) return 'Mot de passe trop courant ou facile à deviner. Choisissez-en un plus original.';
  if (hasSeq(low)) return 'Évitez les suites évidentes (abcd, 1234, azerty, qwerty…).';
  if (/(.)\1{2,}/.test(pw) || new Set(pw).size < 6) return 'Évitez les répétitions (aaa, 111…) : utilisez au moins 6 caractères différents.';
  if (ctx.flatMap(c => String(c).toLowerCase().split(/[^a-z0-9]+/)).some(t => t.length >= 4 && low.includes(t))) return 'Le mot de passe ne doit pas contenir votre nom, votre email ni le nom de la structure.';
  return null;
}

// Blocage : 3 échecs sur un compte => 2 h ; 10 échecs depuis une même adresse IP => 2 h (stocké en base)
async function lockedUntil(keys) {
  const r = await rows(`SELECT bloque_jusqua b FROM tentatives_connexion WHERE cle IN (${keys.map(() => '?').join(',')})`, keys);
  const m = Math.max(0, ...r.map(x => Number(x.b || 0))); return m > Date.now() ? m : 0;
}
async function addFail(k, max) {
  const now = Date.now(), r = await one('SELECT echecs,bloque_jusqua b FROM tentatives_connexion WHERE cle=?', [k]);
  const n = r && !(r.b && Number(r.b) <= now) ? r.echecs + 1 : 1;
  await pool.execute('REPLACE INTO tentatives_connexion (cle,echecs,bloque_jusqua,dernier) VALUES (?,?,?,?)', [k, n, n >= max ? now + LOCK_MS : null, now]);
  return n;
}

const e = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fail = (res, m, c = 422) => res.status(c).json({ ok: false, error: m });
const today = () => new Date(Date.now() - new Date().getTimezoneOffset() * 6e4).toISOString().slice(0, 10);
const validDate = d => /^\d{4}-\d{2}-\d{2}$/.test(d || '') && new Date(d + 'T00:00:00Z').toISOString().slice(0, 10) === d;
const csrf = req => req.session.csrf || (req.session.csrf = crypto.randomBytes(16).toString('hex'));
const csrfOk = req => { const a = Buffer.from(String(req.body?.csrf || '')), b = Buffer.from(req.session.csrf || ''); return a.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b); };
const genCode = () => { const a = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let s = ''; for (let i = 0; i < 4; i++) s += a[crypto.randomInt(32)]; return `GEST_RDV-${new Date().getFullYear()}-${s}`; };
const ent = async () => (await one('SELECT * FROM entreprises ORDER BY id LIMIT 1')) || { nom: 'Ma structure', adresse: '', telephone: '', email: '', couleur: '#6c5ce7' };
const installed = async () => (await one("SELECT COUNT(*) n FROM utilisateurs WHERE role='super_admin'")).n > 0;
const getUser = async req => { if (!req.session.uid) return null; const u = await one('SELECT id,nom,email,role,service_id FROM utilisateurs WHERE id=?', [req.session.uid]); return u ? { ...u, nom: dec(u.nom), email: dec(u.email) } : null; };

function cleanRdv(i, future) {
  const d = {}; for (const k of ['nom', 'prenom', 'telephone', 'email', 'motif']) d[k] = String(i[k] ?? '').trim();
  d.service_id = parseInt(i.service_id) || 0; d.date_souhaitee = String(i.date_souhaitee ?? '').trim();
  if (!d.nom || !d.prenom || d.nom.length > 80 || d.prenom.length > 80) return [null, 'Nom et prénom requis (80 caractères maximum).'];
  if (!/^[0-9+\s().-]{6,25}$/.test(d.telephone)) return [null, 'Numéro de téléphone invalide.'];
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(d.email) || d.email.length > 150) return [null, 'Adresse email invalide.'];
  if (!validDate(d.date_souhaitee) || (future && d.date_souhaitee < today())) return [null, 'Date souhaitée invalide (elle ne peut pas être passée).'];
  if (!d.motif || d.motif.length > 2000) return [null, 'Motif requis (2000 caractères maximum).'];
  return [d, null];
}

// ---------- Gabarit commun ----------
async function send(req, res, title, pg, body, attrs = '') {
  const c = await ent(), u = await getUser(req);
  const items = [['/', 'Accueil', 'index'], ['/demande', 'Demande de RDV', 'demande'], ['/suivi', 'Suivi de RDV', 'suivi'], u ? ['/dashboard', 'Tableau de bord', 'dashboard'] : ['/login', 'Connexion', 'login']];
  res.send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf" content="${e(csrf(req))}"><title>${e(title)} — GEST_RDV</title><link rel="stylesheet" href="/assets/css/style.css"><style>:root{--c:${e(c.couleur)}}</style></head>
<body data-page="${pg}" ${attrs}><div class="blob b1"></div><div class="blob b2"></div><div class="blob b3"></div><div id="bar"></div>
<header class="nav glass"><a class="logo" href="/">GEST_RDV</a><button id="burger" aria-label="Menu">☰</button><nav id="menu">
${items.map(i => `<a href="${i[0]}" class="${pg === i[2] ? 'active' : ''}">${e(i[1])}</a>`).join('')}${u ? '<a href="/logout" class="out">Déconnexion</a>' : ''}</nav></header>
<main class="wrap">${body}</main><footer>© ${new Date().getFullYear()} ${e(c.nom)} — propulsé par <b class="grad">GEST_RDV</b></footer><div id="toasts"></div><script src="/assets/js/main.js"></script></body></html>`);
}

const app = express();
app.disable('x-powered-by');
if (cfg.trustProxy) app.set('trust proxy', 1);
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin', 'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'" }); next(); });
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: true, cookie: { httpOnly: true, sameSite: 'lax', secure: !!cfg.https } }));
app.use('/assets', express.static(path.join(__dirname, 'public/assets')));
const wrap = f => (req, res) => f(req, res).catch(err => {
  console.error(err);
  if (req.method === 'GET' && !req.query.api) return res.status(500).send("Erreur serveur : vérifiez la connexion MySQL (config.js) et l'import de database/base.sql.");
  res.status(500).json({ ok: false, error: 'Erreur base de données.' });
});
const badCsrf = (req, res) => !csrfOk(req) && (fail(res, 'Session invalide, rechargez la page.', 403), true);

// ---------- Accueil ----------
app.get('/', wrap(async (req, res) => {
  if (!await installed()) return res.redirect('/install');
  const c = await ent(), sv = await rows('SELECT nom,description FROM services ORDER BY nom'), n = (await one('SELECT COUNT(*) n FROM rendez_vous')).n;
  await send(req, res, 'Accueil', 'index', `
<section class="hero"><h1 class="logo-big grad">GEST_RDV</h1><h2 class="typing" data-text="Gérez vos rendez-vous, simplement."></h2>
<p class="mut">Une plateforme unique pour recevoir, suivre et traiter les demandes de rendez-vous de <b>${e(c.nom)}</b>.</p>
<div class="row"><a class="btn" href="/demande">Demander un rendez-vous</a><a class="btn ghost" href="/suivi">Suivre ma demande</a></div></section>
<section class="grid">
<article class="card glass pad"><h3 class="u">Notre structure</h3><p><b>${e(c.nom)}</b></p>
${c.adresse ? `<p class="mut">📍 ${e(c.adresse)}</p>` : ''}${c.telephone ? `<p class="mut">📞 <a href="tel:${e(c.telephone)}">${e(c.telephone)}</a></p>` : ''}${c.email ? `<p class="mut">✉️ <a href="mailto:${e(c.email)}">${e(c.email)}</a></p>` : ''}</article>
<article class="card glass pad"><h3 class="u">En chiffres</h3><p class="big">${n}</p><p class="mut">demande(s) de rendez-vous enregistrée(s)</p><p class="big">${sv.length}</p><p class="mut">service(s) / direction(s)</p></article>
<article class="card glass pad"><h3 class="u">Services</h3>${sv.length ? '' : '<p class="mut">Aucun service n’a encore été créé.</p>'}
${sv.map(s => `<p><b>${e(s.nom)}</b>${s.description ? `<br><span class="mut">${e(s.description)}</span>` : ''}</p>`).join('')}</article></section>`);
}));

// ---------- Installation ----------
app.get('/install', wrap(async (req, res) => {
  const done = await installed();
  await send(req, res, 'Installation', 'install', `<section class="card glass pad narrow"><h1 class="grad">Installation</h1>${done
    ? `<p>GEST_RDV est déjà installé. Pour votre sécurité, ne laissez pas cette page accessible en production.</p><a class="btn" href="/login">Se connecter</a>`
    : `<p class="mut">Créez votre structure et le premier compte Super Admin.</p><form data-ajax data-redirect="/login" method="post"><input type="hidden" name="do" value="install">
<label class="field">Nom de la structure<input name="entreprise" required maxlength="150"></label><label class="field">Votre nom<input name="nom" required maxlength="120"></label>
<label class="field">Email de connexion<input type="email" name="email" required></label><label class="field">Mot de passe (10 car. min. : majuscule, minuscule, chiffre et symbole)<input type="password" name="mot_de_passe" required minlength="10" maxlength="72" autocomplete="new-password"></label>
<button class="btn" type="submit">Créer le Super Admin</button></form>`}</section>`);
}));
app.post('/install', wrap(async (req, res) => {
  if (badCsrf(req, res)) return;
  if (await installed()) return fail(res, 'GEST_RDV est déjà installé.', 403);
  const b = req.body, ent_ = String(b.entreprise || '').trim(), nom = String(b.nom || '').trim(), mail = String(b.email || '').trim(), pw = String(b.mot_de_passe || '');
  if (!ent_ || ent_.length > 150) return fail(res, 'Nom de la structure requis.');
  if (!nom) return fail(res, 'Nom de l’administrateur requis.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) return fail(res, 'Email invalide.');
  const pe = pwError(pw, [nom, mail.split('@')[0], ent_]); if (pe) return fail(res, pe);
  const hash = await bcrypt.hash(pw, COST), cn = await pool.getConnection();
  try {
    await cn.beginTransaction();
    if ((await cn.query('SELECT COUNT(*) n FROM entreprises'))[0][0].n > 0) await cn.execute('UPDATE entreprises SET nom=? ORDER BY id LIMIT 1', [ent_]);
    else await cn.execute('INSERT INTO entreprises (nom) VALUES (?)', [ent_]);
    await cn.execute("INSERT INTO utilisateurs (nom,email,email_idx,mot_de_passe,role) VALUES (?,?,?,?,'super_admin')", [enc(nom), enc(mail), bidx(mail), hash]);
    await cn.commit();
  } catch (err) { await cn.rollback(); return fail(res, err.code === 'ER_DUP_ENTRY' ? 'Email déjà utilisé.' : 'Installation impossible.', 500); } finally { cn.release(); }
  res.json({ ok: true, message: 'Super Admin créé. Redirection vers la connexion…' });
}));

// ---------- Demande ----------
app.get('/demande', wrap(async (req, res) => {
  const sv = await rows('SELECT id,nom FROM services ORDER BY nom');
  await send(req, res, 'Demande de rendez-vous', 'demande', `<section class="card glass pad narrow"><h1 class="grad u">Demande de rendez-vous</h1>${!sv.length ? '<p class="mut">Aucun service n’est disponible pour le moment. Revenez plus tard.</p>' : `
<form id="fDemande" data-ajax method="post"><input type="hidden" name="do" value="demande"><div class="two">
<label class="field">Nom<input name="nom" required maxlength="80"></label><label class="field">Prénom<input name="prenom" required maxlength="80"></label>
<label class="field">Téléphone<input name="telephone" type="tel" required maxlength="25"></label><label class="field">Email<input name="email" type="email" required maxlength="150"></label>
<label class="field">Service<select name="service_id" required><option value="">Choisir…</option>${sv.map(s => `<option value="${s.id}">${e(s.nom)}</option>`).join('')}</select></label>
<label class="field">Date souhaitée<input type="date" name="date_souhaitee" required min="${today()}"></label></div>
<label class="field">Motif<textarea name="motif" rows="4" required maxlength="2000"></textarea></label><button class="btn" type="submit">Envoyer la demande</button></form><div id="res" class="result" hidden></div>`}</section>`);
}));
app.post('/demande', wrap(async (req, res) => {
  if (badCsrf(req, res)) return;
  const [d, err] = cleanRdv(req.body, true); if (err) return fail(res, err);
  if (!await one('SELECT id FROM services WHERE id=?', [d.service_id])) return fail(res, 'Service inconnu.');
  for (let i = 0; i < 10; i++) {
    const code = genCode();
    try {
      await pool.execute('INSERT INTO rendez_vous (code_suivi,nom,prenom,telephone,email,service_id,date_souhaitee,motif) VALUES (?,?,?,?,?,?,?,?)', [code, enc(d.nom), enc(d.prenom), enc(d.telephone), enc(d.email), d.service_id, d.date_souhaitee, enc(d.motif)]);
      return res.json({ ok: true, code, message: 'Demande enregistrée.' });
    } catch (x) { if (x.code !== 'ER_DUP_ENTRY') throw x; }
  }
  fail(res, 'Impossible de générer un code, réessayez.', 500);
}));

// ---------- Suivi ----------
app.get('/suivi', wrap(async (req, res) => {
  await send(req, res, 'Suivi de rendez-vous', 'suivi', `<section class="card glass pad narrow"><h1 class="grad u">Suivi de rendez-vous</h1>
<form id="fSuivi" data-ajax method="post"><input type="hidden" name="do" value="suivi"><label class="field">Code de suivi<input name="code" required maxlength="30" placeholder="GEST_RDV-${new Date().getFullYear()}-XXXX" value="${e(req.query.code || '')}"></label>
<button class="btn" type="submit">Consulter le statut</button></form><div id="res" class="result" hidden></div></section>`);
}));
app.post('/suivi', wrap(async (req, res) => {
  if (badCsrf(req, res)) return;
  const now = Date.now(); req.session.sv = (req.session.sv || []).filter(t => t > now - 600000);
  if (req.session.sv.length >= 20) return fail(res, 'Trop de recherches. Réessayez dans quelques minutes.', 429);
  req.session.sv.push(now);
  const r = await one(`SELECT r.code_suivi,r.nom,r.prenom,r.statut,r.date_souhaitee,r.motif_report_refus,r.date_creation,s.nom AS service FROM rendez_vous r JOIN services s ON s.id=r.service_id WHERE r.code_suivi=?`, [String(req.body.code || '').trim().toUpperCase()]);
  if (!r) return fail(res, 'Aucun rendez-vous ne correspond à ce code.', 404);
  res.json({ ok: true, rdv: { ...r, nom: dec(r.nom), prenom: dec(r.prenom), motif_report_refus: dec(r.motif_report_refus) } });
}));

// ---------- Connexion ----------
app.get('/login', wrap(async (req, res) => {
  if (!await installed()) return res.redirect('/install');
  if (await getUser(req)) return res.redirect('/dashboard');
  await send(req, res, 'Connexion', 'login', `<section class="card glass pad narrow"><h1 class="grad u">Connexion</h1><form data-ajax data-redirect="/dashboard" method="post"><input type="hidden" name="do" value="login">
<label class="field">Email<input type="email" name="email" required autocomplete="username"></label><label class="field">Mot de passe<input type="password" name="mot_de_passe" required autocomplete="current-password"></label>
<button class="btn" type="submit">Se connecter</button></form></section>`);
}));
app.post('/login', wrap(async (req, res) => {
  if (badCsrf(req, res)) return;
  const mail = String(req.body.email || '').trim().toLowerCase().slice(0, 150), pw = String(req.body.mot_de_passe || '').slice(0, 200);
  const kMail = 'mail:' + bidx(mail), kIp = 'ip:' + req.ip, until = await lockedUntil([kMail, kIp]);
  if (until) return fail(res, `Trop de tentatives : accès bloqué pour 2 heures. Réessayez dans ${Math.ceil((until - Date.now()) / 60000)} minute(s).`, 429);
  const u = await one('SELECT id,mot_de_passe FROM utilisateurs WHERE email_idx=?', [bidx(mail)]);
  const ok = await bcrypt.compare(pw, u ? u.mot_de_passe : DUMMY_HASH);
  if (!u || !ok) {
    const n = await addFail(kMail, MAX_FAILS); await addFail(kIp, MAX_IP_FAILS);
    return fail(res, n >= MAX_FAILS ? 'Trop de tentatives : accès bloqué pour 2 heures.' : `Email ou mot de passe incorrect. Il vous reste ${MAX_FAILS - n} tentative(s).`, n >= MAX_FAILS ? 429 : 401);
  }
  await pool.execute('DELETE FROM tentatives_connexion WHERE cle IN (?,?)', [kMail, kIp]);
  await new Promise((ok2, ko) => req.session.regenerate(er => er ? ko(er) : ok2()));
  req.session.uid = u.id; res.json({ ok: true, message: 'Connexion réussie.' });
}));
app.get('/logout', (req, res) => req.session.destroy(() => { res.clearCookie('connect.sid'); res.redirect('/login'); }));

// ---------- Tableau de bord ----------
const ADMIN_ACTS = ['users', 'service_save', 'service_delete', 'user_save', 'user_delete', 'entreprise_save'];
async function dashApi(req, res, u, act) {
  const admin = u.role === 'super_admin', b = req.body || {}, q = req.query;
  if (req.method === 'POST' && badCsrf(req, res)) return;
  if (ADMIN_ACTS.includes(act) && !admin) return fail(res, 'Accès réservé au Super Admin.', 403);
  let w = '', p = []; if (!admin) { w = ' AND r.service_id=?'; p = [u.service_id ?? 0]; }
  const find = async () => { const r = await one(`SELECT r.* FROM rendez_vous r WHERE r.id=? ${w}`, [parseInt(b.rid) || 0, ...p]); if (!r) fail(res, 'Rendez-vous introuvable ou non autorisé.', 404); return r; };
  switch (act) {
    case 'stats': {
      const r = await one(`SELECT COUNT(*) total, COALESCE(SUM(r.statut='En attente'),0) attente, COALESCE(SUM(r.statut='Validé'),0) valide, COALESCE(SUM(r.statut='Refusé'),0) refuse, COALESCE(SUM(r.statut='Reporté'),0) reporte FROM rendez_vous r WHERE 1=1 ${w}`, p);
      return res.json({ ok: true, ...Object.fromEntries(Object.entries(r).map(([k, v]) => [k, Number(v)])) });
    }
    case 'list': {
      const t = String(q.q || '').trim().toLowerCase(), st = String(q.statut || ''), d = String(q.date || '');
      if (STATUTS.includes(st)) { w += ' AND r.statut=?'; p.push(st); }
      if (validDate(d)) { w += ' AND r.date_souhaitee=?'; p.push(d); }
      // Les données personnelles étant chiffrées, la recherche se fait après déchiffrement (en mémoire du serveur)
      let list = (await rows(`SELECT r.*, s.nom AS service FROM rendez_vous r LEFT JOIN services s ON s.id=r.service_id WHERE 1=1 ${w} ORDER BY r.date_creation DESC, r.id DESC LIMIT 5000`, p)).map(decRdv);
      if (t) list = list.filter(r => [r.nom, r.prenom, r.telephone, r.code_suivi].some(v => String(v).toLowerCase().includes(t)));
      return res.json({ ok: true, rows: list.slice(0, 500) });
    }
    case 'services': return res.json({ ok: true, rows: await rows('SELECT s.*, (SELECT COUNT(*) FROM rendez_vous r WHERE r.service_id=s.id) AS nb FROM services s ORDER BY s.nom') });
    case 'users': return res.json({ ok: true, rows: (await rows('SELECT u.id,u.nom,u.email,u.role,u.service_id,s.nom AS service FROM utilisateurs u LEFT JOIN services s ON s.id=u.service_id')).map(x => ({ ...x, nom: dec(x.nom), email: dec(x.email) })).sort((a, b) => a.nom.localeCompare(b.nom)) });
    case 'rdv_save': {
      const r = await find(); if (!r) return;
      if (!admin) b.service_id = r.service_id;
      const [d, err] = cleanRdv(b, false); if (err) return fail(res, err);
      if (!await one('SELECT id FROM services WHERE id=?', [d.service_id])) return fail(res, 'Service inconnu.');
      await pool.execute('UPDATE rendez_vous SET nom=?,prenom=?,telephone=?,email=?,service_id=?,date_souhaitee=?,motif=? WHERE id=?', [enc(d.nom), enc(d.prenom), enc(d.telephone), enc(d.email), d.service_id, d.date_souhaitee, enc(d.motif), r.id]);
      return res.json({ ok: true, message: 'Rendez-vous modifié.' });
    }
    case 'rdv_statut': {
      const r = await find(); if (!r) return;
      const st = b.statut; if (!STATUTS.includes(st)) return fail(res, 'Statut invalide.');
      let m = String(b.motif_report_refus || '').trim(), nd = r.date_souhaitee;
      if ((st === 'Reporté' || st === 'Refusé') && !m) return fail(res, 'Un motif est obligatoire pour un report ou un refus.');
      if (st === 'Reporté') { nd = b.nouvelle_date; if (!validDate(nd)) return fail(res, 'Nouvelle date requise pour un report.'); }
      if (st !== 'Reporté' && st !== 'Refusé') m = null;
      await pool.execute('UPDATE rendez_vous SET statut=?, motif_report_refus=?, date_souhaitee=? WHERE id=?', [st, enc(m), nd, r.id]);
      return res.json({ ok: true, message: 'Statut mis à jour : ' + st + '.' });
    }
    case 'rdv_delete': { const r = await find(); if (!r) return; await pool.execute('DELETE FROM rendez_vous WHERE id=?', [r.id]); return res.json({ ok: true, message: 'Rendez-vous supprimé.' }); }
    case 'service_save': {
      const id = parseInt(b.sid) || 0, n = String(b.nom || '').trim(), ds = String(b.description || '').trim();
      if (!n || n.length > 120 || ds.length > 500) return fail(res, 'Nom requis (120 car. max), description 500 car. max.');
      try { id ? await pool.execute('UPDATE services SET nom=?,description=? WHERE id=?', [n, ds, id]) : await pool.execute('INSERT INTO services (nom,description) VALUES (?,?)', [n, ds]); }
      catch (x) { if (x.code === 'ER_DUP_ENTRY') return fail(res, 'Ce service existe déjà.'); throw x; }
      return res.json({ ok: true, message: id ? 'Service modifié.' : 'Service créé.' });
    }
    case 'service_delete':
      try { await pool.execute('DELETE FROM services WHERE id=?', [parseInt(b.sid) || 0]); } catch (x) { return fail(res, 'Suppression impossible : ce service contient des rendez-vous ou des utilisateurs.'); }
      return res.json({ ok: true, message: 'Service supprimé.' });
    case 'user_save': {
      const id = parseInt(b.uid) || 0, n = String(b.nom || '').trim(), m = String(b.email || '').trim(), role = b.role, pw = String(b.mot_de_passe || '');
      let sid = parseInt(b.service_id) || 0;
      if (!n || n.length > 120) return fail(res, 'Nom requis.');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(m)) return fail(res, 'Email invalide.');
      if (!['super_admin', 'agent'].includes(role)) return fail(res, 'Rôle invalide.');
      if (role === 'agent') { if (!await one('SELECT id FROM services WHERE id=?', [sid])) return fail(res, 'Un agent doit être rattaché à un service.'); } else sid = null;
      if (id && id === u.id && role !== 'super_admin') return fail(res, 'Vous ne pouvez pas retirer votre propre rôle Super Admin.');
      if (!id || pw) { const pe = pwError(pw, [n, m.split('@')[0]]); if (pe) return fail(res, pe); }
      try {
        if (id) { await pool.execute('UPDATE utilisateurs SET nom=?,email=?,email_idx=?,role=?,service_id=? WHERE id=?', [enc(n), enc(m), bidx(m), role, sid, id]); if (pw) await pool.execute('UPDATE utilisateurs SET mot_de_passe=? WHERE id=?', [await bcrypt.hash(pw, COST), id]); }
        else await pool.execute('INSERT INTO utilisateurs (nom,email,email_idx,mot_de_passe,role,service_id) VALUES (?,?,?,?,?,?)', [enc(n), enc(m), bidx(m), await bcrypt.hash(pw, COST), role, sid]);
      } catch (x) { if (x.code === 'ER_DUP_ENTRY') return fail(res, 'Cet email est déjà utilisé.'); throw x; }
      return res.json({ ok: true, message: id ? 'Utilisateur modifié.' : 'Utilisateur créé.' });
    }
    case 'user_delete': {
      const id = parseInt(b.uid) || 0; if (id === u.id) return fail(res, 'Vous ne pouvez pas supprimer votre propre compte.');
      await pool.execute('DELETE FROM utilisateurs WHERE id=?', [id]); return res.json({ ok: true, message: 'Utilisateur supprimé.' });
    }
    case 'entreprise_save': {
      const n = String(b.nom || '').trim(), a = String(b.adresse || '').trim(), t = String(b.telephone || '').trim(), m = String(b.email || '').trim(), c = String(b.couleur || '').trim();
      if (!n || n.length > 150) return fail(res, 'Nom de la structure requis.');
      if (a.length > 255 || t.length > 30) return fail(res, 'Adresse ou téléphone trop long.');
      if (m && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(m)) return fail(res, 'Email invalide.');
      if (!/^#[0-9a-fA-F]{6}$/.test(c)) return fail(res, 'Couleur invalide.');
      if ((await one('SELECT COUNT(*) n FROM entreprises')).n > 0) await pool.execute('UPDATE entreprises SET nom=?,adresse=?,telephone=?,email=?,couleur=? ORDER BY id LIMIT 1', [n, a, t, m, c]);
      else await pool.execute('INSERT INTO entreprises (nom,adresse,telephone,email,couleur) VALUES (?,?,?,?,?)', [n, a, t, m, c]);
      return res.json({ ok: true, message: 'Paramètres enregistrés.', couleur: c });
    }
    default: return fail(res, 'Action inconnue.', 400);
  }
}
const dash = wrap(async (req, res) => {
  const u = await getUser(req), act = req.query.api ?? req.body?.do;
  if (!u) { if (act != null) return fail(res, 'Session expirée, reconnectez-vous.', 401); return res.redirect('/login'); }
  if (act != null) return dashApi(req, res, u, act);
  const admin = u.role === 'super_admin', c = await ent();
  const sn = u.service_id ? (await one('SELECT nom FROM services WHERE id=?', [u.service_id]))?.nom || '' : '';
  const opts = STATUTS.map(s => `<option>${e(s)}</option>`).join('');
  await send(req, res, 'Tableau de bord', 'dashboard', `
<section class="hero-sm"><h1 class="grad u">Tableau de bord</h1><p class="mut">Bonjour <b>${e(u.nom)}</b> — ${admin ? 'Super Admin (tous les services)' : 'Agent / Direction : ' + e(sn)}</p></section>
<div class="tabs glass"><button class="tab on" data-t="rdv">Rendez-vous</button>${admin ? '<button class="tab" data-t="services">Services</button><button class="tab" data-t="users">Utilisateurs</button><button class="tab" data-t="ent">Paramètres</button>' : ''}</div>
<section id="t-rdv" class="pane on"><div class="stats"><div class="card glass stat"><span id="s-total">–</span>Total</div><div class="card glass stat w"><span id="s-attente">–</span>En attente</div><div class="card glass stat v"><span id="s-valide">–</span>Validés</div><div class="card glass stat x"><span id="s-refuse">–</span>Refusés</div><div class="card glass stat r"><span id="s-reporte">–</span>Reportés</div></div>
<div class="glass pad filters"><input id="fq" type="search" placeholder="Rechercher : nom, téléphone ou code"><select id="fs"><option value="">Tous les statuts</option>${opts}</select><input id="fd" type="date" title="Date souhaitée"><button class="btn ghost" id="freset" type="button">Réinitialiser</button></div>
<div class="glass pad tw"><table><thead><tr><th>Code</th><th>Demandeur</th><th>Service</th><th>Date</th><th>Statut</th><th>Actions</th></tr></thead><tbody id="rows"></tbody></table><p id="empty" class="mut" hidden>Aucun rendez-vous ne correspond à votre recherche.</p></div></section>
${admin ? `<section id="t-services" class="pane"><div class="glass pad"><h3 class="u">Service / direction</h3><form data-ajax method="post" class="two"><input type="hidden" name="do" value="service_save"><input type="hidden" name="sid">
<label class="field">Nom<input name="nom" required maxlength="120"></label><label class="field">Description<input name="description" maxlength="500"></label><div class="row"><button class="btn" type="submit">Enregistrer</button><button class="btn ghost" type="button" data-reset>Nouveau</button></div></form></div>
<div class="glass pad tw"><table><thead><tr><th>Nom</th><th>Description</th><th>RDV</th><th>Actions</th></tr></thead><tbody id="srows"></tbody></table></div></section>
<section id="t-users" class="pane"><div class="glass pad"><h3 class="u">Compte utilisateur</h3><form data-ajax method="post" class="two"><input type="hidden" name="do" value="user_save"><input type="hidden" name="uid">
<label class="field">Nom<input name="nom" required maxlength="120"></label><label class="field">Email<input type="email" name="email" required></label>
<label class="field">Mot de passe <small class="mut">(vide = inchangé ; 10 car. min., majuscule, minuscule, chiffre, symbole)</small><input type="password" name="mot_de_passe" minlength="10" maxlength="72" autocomplete="new-password"></label>
<label class="field">Rôle<select name="role" id="urole"><option value="agent">Agent / Direction</option><option value="super_admin">Super Admin</option></select></label>
<label class="field" id="usvc">Service<select name="service_id" class="svc-opts"></select></label><div class="row"><button class="btn" type="submit">Enregistrer</button><button class="btn ghost" type="button" data-reset>Nouveau</button></div></form></div>
<div class="glass pad tw"><table><thead><tr><th>Nom</th><th>Email</th><th>Rôle</th><th>Service</th><th>Actions</th></tr></thead><tbody id="urows"></tbody></table></div></section>
<section id="t-ent" class="pane"><div class="glass pad"><h3 class="u">Paramètres de la structure</h3><form data-ajax method="post" class="two"><input type="hidden" name="do" value="entreprise_save">
<label class="field">Nom<input name="nom" required maxlength="150" value="${e(c.nom)}"></label><label class="field">Adresse<input name="adresse" maxlength="255" value="${e(c.adresse)}"></label>
<label class="field">Téléphone<input name="telephone" maxlength="30" value="${e(c.telephone)}"></label><label class="field">Email<input type="email" name="email" maxlength="150" value="${e(c.email)}"></label>
<label class="field">Couleur principale<input type="color" name="couleur" value="${e(c.couleur)}"></label><div class="row"><button class="btn" type="submit">Enregistrer</button></div></form></div></section>` : ''}
<dialog id="mEdit" class="glass"><form data-ajax method="post" id="fEdit"><h3 class="u">Modifier le rendez-vous</h3><input type="hidden" name="do" value="rdv_save"><input type="hidden" name="rid"><div class="two">
<label class="field">Nom<input name="nom" required maxlength="80"></label><label class="field">Prénom<input name="prenom" required maxlength="80"></label><label class="field">Téléphone<input name="telephone" required maxlength="25"></label>
<label class="field">Email<input type="email" name="email" required></label><label class="field">Service<select name="service_id" class="svc-opts" ${admin ? '' : 'disabled'}></select></label><label class="field">Date souhaitée<input type="date" name="date_souhaitee" required></label></div>
<label class="field">Motif<textarea name="motif" rows="3" required maxlength="2000"></textarea></label><div class="row"><button class="btn" type="submit">Enregistrer</button><button class="btn ghost" type="button" data-close>Annuler</button></div></form></dialog>
<dialog id="mStat" class="glass"><form data-ajax method="post" id="fStat"><h3 class="u">Changer le statut</h3><input type="hidden" name="do" value="rdv_statut"><input type="hidden" name="rid">
<label class="field">Statut<select name="statut" id="stSel">${opts}</select></label><label class="field" id="stDate" hidden>Nouvelle date<input type="date" name="nouvelle_date"></label>
<label class="field" id="stMotif" hidden>Motif<textarea name="motif_report_refus" rows="3" maxlength="1000"></textarea></label><div class="row"><button class="btn" type="submit">Appliquer</button><button class="btn ghost" type="button" data-close>Annuler</button></div></form></dialog>`,
    `data-admin="${admin ? 1 : 0}"`);
});
app.get('/dashboard', dash); app.post('/dashboard', dash);


// Migration automatique : crée la table de blocage, passe les colonnes en mode chiffré et chiffre les anciennes données en clair
async function migrate() {
  await pool.query('CREATE TABLE IF NOT EXISTS tentatives_connexion (cle VARCHAR(100) PRIMARY KEY, echecs INT NOT NULL DEFAULT 0, bloque_jusqua BIGINT NULL, dernier BIGINT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
  const has = async (t, c) => (await one('SELECT COUNT(*) n FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?', [t, c])).n > 0;
  if (!await has('utilisateurs', 'email_idx')) {
    await pool.query('ALTER TABLE utilisateurs DROP INDEX email').catch(() => {});
    await pool.query('ALTER TABLE utilisateurs MODIFY nom TEXT NOT NULL, MODIFY email TEXT NOT NULL, ADD COLUMN email_idx CHAR(64) NULL');
    for (const u of await rows('SELECT id,nom,email FROM utilisateurs')) { const m = dec(u.email); await pool.execute('UPDATE utilisateurs SET nom=?,email=?,email_idx=? WHERE id=?', [enc(dec(u.nom)), enc(m), bidx(m), u.id]); }
    await pool.query('ALTER TABLE utilisateurs MODIFY email_idx CHAR(64) NOT NULL, ADD UNIQUE KEY uq_email_idx (email_idx)');
  }
  const t = await one("SELECT DATA_TYPE t FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='rendez_vous' AND COLUMN_NAME='nom'");
  if (t.t !== 'text') await pool.query('ALTER TABLE rendez_vous MODIFY nom TEXT NOT NULL, MODIFY prenom TEXT NOT NULL, MODIFY telephone TEXT NOT NULL, MODIFY email TEXT NOT NULL');
  for (const r of await rows("SELECT * FROM rendez_vous WHERE nom NOT LIKE 'v1:%' OR motif NOT LIKE 'v1:%'"))
    await pool.execute('UPDATE rendez_vous SET nom=?,prenom=?,telephone=?,email=?,motif=?,motif_report_refus=? WHERE id=?', [enc(dec(r.nom)), enc(dec(r.prenom)), enc(dec(r.telephone)), enc(dec(r.email)), enc(dec(r.motif)), r.motif_report_refus && !String(r.motif_report_refus).startsWith('v1:') ? enc(r.motif_report_refus) : r.motif_report_refus, r.id]);
}
migrate().then(() => app.listen(cfg.port, () => console.log(`GEST_RDV démarré : http://localhost:${cfg.port}`)))
  .catch(err => { console.error("Démarrage impossible. Vérifiez config.js et l'import de database/base.sql :", err.message); process.exit(1); });
