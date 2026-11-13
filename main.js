(() => {
const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const csrf = () => $('meta[name=csrf]')?.content || '';

function toast(msg, type = 'ok') {
  const t = document.createElement('div'); t.className = 'toast ' + type; t.textContent = msg;
  $('#toasts').appendChild(t);
  t.addEventListener('click', () => t.remove());
  setTimeout(() => { t.style.transition = '.4s'; t.style.opacity = 0; setTimeout(() => t.remove(), 400); }, 4500);
}

// Requête réelle vers le serveur avec barre de chargement liée à la durée de la requête
let pending = 0;
async function api(url, data) {
  const bar = $('#bar'); pending++; bar.classList.add('on');
  try {
    const opt = { headers: { 'X-Requested-With': 'fetch' } };
    if (data) { if (!data.has('csrf')) data.append('csrf', csrf()); opt.method = 'POST'; opt.body = new URLSearchParams(data); }
    const r = await fetch(url, opt);
    let j; try { j = await r.json(); } catch { throw new Error('Réponse invalide du serveur.'); }
    if (!r.ok || j.ok === false) throw new Error(j.error || 'Erreur serveur.');
    return j;
  } finally { if (--pending === 0) { bar.classList.remove('on'); bar.style.width = '100%'; setTimeout(() => bar.style.width = '', 300); } }
}

// Menu mobile + transitions de page
$('#burger')?.addEventListener('click', () => $('#menu').classList.toggle('open'));
window.addEventListener('pageshow', () => document.body.classList.remove('leave'));
document.addEventListener('click', e => {
  const a = e.target.closest('a[href]'); if (!a) return;
  const h = a.getAttribute('href');
  if (!h || h[0] === '#' || a.target || e.ctrlKey || e.metaKey || e.shiftKey || /^(https?:|mailto:|tel:)/.test(h)) return;
  e.preventDefault(); document.body.classList.add('leave');
  document.body.addEventListener('transitionend', () => location.href = h, { once: true });
});

// Texte lettre par lettre
$$('.typing').forEach(el => {
  const t = el.dataset.text; let i = 0;
  const iv = setInterval(() => { el.textContent = t.slice(0, ++i); if (i >= t.length) clearInterval(iv); }, 55);
});

// Formulaires AJAX génériques
$$('form[data-ajax]').forEach(f => f.addEventListener('submit', async ev => {
  ev.preventDefault();
  const b = $('button[type=submit]', f); b.disabled = true; b.classList.add('busy');
  try {
    const fd = new FormData(f); const j = await api(f.getAttribute('action') || location.pathname, fd);
    if (j.message) toast(j.message);
    f.dispatchEvent(new CustomEvent('done', { bubbles: true, detail: { ...j, do: fd.get('do') } }));
    if (f.dataset.redirect) setTimeout(() => location.href = f.dataset.redirect, 500);
  } catch (err) { toast(err.message, 'err'); }
  finally { b.disabled = false; b.classList.remove('busy'); }
}));

// Page demande
$('#fDemande')?.addEventListener('done', e => {
  const r = $('#res'); r.hidden = false;
  r.innerHTML = `<p>Votre demande est enregistrée. Conservez ce code pour la suivre :</p><p class="code grad">${esc(e.detail.code)}</p><a class="btn" href="/suivi?code=${encodeURIComponent(e.detail.code)}">Suivre ma demande</a>`;
  e.target.reset();
});

// Page suivi
const BADGE = { 'En attente': 'w', 'Validé': 'v', 'Reporté': 'r', 'Refusé': 'x' };
const fSuivi = $('#fSuivi');
if (fSuivi) {
  fSuivi.addEventListener('done', e => {
    const r = e.detail.rdv, box = $('#res'); box.hidden = false;
    box.innerHTML = `<p class="code grad">${esc(r.code_suivi)}</p>
      <p><span class="badge ${BADGE[r.statut]}">${esc(r.statut)}</span></p>
      <p><b>${esc(r.prenom)} ${esc(r.nom)}</b> — ${esc(r.service)}</p>
      <p class="mut">Date ${r.statut === 'Reporté' ? 'reportée au' : 'souhaitée :'} ${esc(r.date_souhaitee)} · Demande créée le ${esc(r.date_creation)}</p>
      ${r.motif_report_refus ? `<p><b>Motif :</b> ${esc(r.motif_report_refus)}</p>` : ''}`;
  });
  fSuivi.addEventListener('submit', () => { $('#res').hidden = true; });
  if (fSuivi.elements.code.value) fSuivi.requestSubmit();
}

// Tableau de bord
if (document.body.dataset.page === 'dashboard') {
  const ST = BADGE, admin = document.body.dataset.admin === '1';
  const rows = new Map(), svcs = new Map(), users = new Map();
  const safe = fn => fn().catch(err => toast(err.message, 'err'));
  const fill = (form, obj) => { for (const [k, v] of Object.entries(obj)) { const el = form.elements[k]; if (el && el.type !== 'file') el.value = v ?? ''; } };
  const clearForm = f => { f.reset(); $$('input[type=hidden]', f).forEach(h => { if (!['do', 'csrf'].includes(h.name)) h.value = ''; }); };

  async function loadStats() {
    const j = await api('/dashboard?api=stats');
    for (const k of ['total', 'attente', 'valide', 'refuse', 'reporte']) $('#s-' + k).textContent = j[k];
  }
  async function loadList() {
    const q = new URLSearchParams({ api: 'list', q: $('#fq').value, statut: $('#fs').value, date: $('#fd').value });
    const j = await api('/dashboard?' + q); rows.clear();
    $('#rows').innerHTML = j.rows.map(r => { rows.set(String(r.id), r); return `<tr>
      <td><b>${esc(r.code_suivi)}</b></td>
      <td>${esc(r.prenom)} ${esc(r.nom)}<small>${esc(r.telephone)} · ${esc(r.email)}</small><small>${esc(r.motif)}</small></td>
      <td>${esc(r.service || '—')}</td><td>${esc(r.date_souhaitee)}</td>
      <td><span class="badge ${ST[r.statut]}">${esc(r.statut)}</span>${r.motif_report_refus ? `<small>${esc(r.motif_report_refus)}</small>` : ''}</td>
      <td class="act"><button class="mini" data-a="stat" data-id="${r.id}">Statut</button><button class="mini" data-a="edit" data-id="${r.id}">Modifier</button><button class="mini red" data-a="del" data-id="${r.id}">Supprimer</button></td></tr>`; }).join('');
    $('#empty').hidden = j.rows.length > 0;
  }
  async function loadServices() {
    const j = await api('/dashboard?api=services'); svcs.clear(); j.rows.forEach(s => svcs.set(String(s.id), s));
    const opts = j.rows.map(s => `<option value="${s.id}">${esc(s.nom)}</option>`).join('');
    $$('.svc-opts').forEach(sel => { const v = sel.value; sel.innerHTML = opts; sel.value = v; });
    if (admin) $('#srows').innerHTML = j.rows.map(s => `<tr><td><b>${esc(s.nom)}</b></td><td>${esc(s.description)}</td><td>${s.nb}</td>
      <td class="act"><button class="mini" data-a="sedit" data-id="${s.id}">Modifier</button><button class="mini red" data-a="sdel" data-id="${s.id}">Supprimer</button></td></tr>`).join('') || '<tr><td colspan="4" class="mut">Aucun service. Créez le premier ci-dessus.</td></tr>';
  }
  async function loadUsers() {
    const j = await api('/dashboard?api=users'); users.clear(); j.rows.forEach(u => users.set(String(u.id), u));
    $('#urows').innerHTML = j.rows.map(u => `<tr><td><b>${esc(u.nom)}</b></td><td>${esc(u.email)}</td><td>${u.role === 'super_admin' ? 'Super Admin' : 'Agent / Direction'}</td><td>${esc(u.service || '—')}</td>
      <td class="act"><button class="mini" data-a="uedit" data-id="${u.id}">Modifier</button><button class="mini red" data-a="udel" data-id="${u.id}">Supprimer</button></td></tr>`).join('');
  }
  const post = async obj => { const fd = new FormData(); for (const k in obj) fd.append(k, obj[k]); return api('/dashboard', fd); };

  // Onglets
  $$('.tab').forEach(t => t.addEventListener('click', () => {
    $$('.tab').forEach(x => x.classList.toggle('on', x === t)); $$('.pane').forEach(p => p.classList.toggle('on', p.id === 't-' + t.dataset.t));
    if (t.dataset.t === 'services') safe(loadServices); if (t.dataset.t === 'users') safe(async () => { await loadServices(); await loadUsers(); });
  }));

  // Recherche + filtres (requêtes SQL à chaque changement)
  let tm; $('#fq').addEventListener('input', () => { clearTimeout(tm); tm = setTimeout(() => safe(loadList), 300); });
  $('#fs').addEventListener('change', () => safe(loadList)); $('#fd').addEventListener('change', () => safe(loadList));
  $('#freset').addEventListener('click', () => { $('#fq').value = ''; $('#fs').value = ''; $('#fd').value = ''; safe(loadList); });

  // Dialogues
  $$('[data-close]').forEach(b => b.addEventListener('click', () => b.closest('dialog').close()));
  $$('[data-reset]').forEach(b => b.addEventListener('click', () => { clearForm(b.closest('form')); toggleSvc(); }));
  const syncStat = () => { const s = $('#stSel').value; $('#stDate').hidden = s !== 'Reporté'; $('#stMotif').hidden = !(s === 'Reporté' || s === 'Refusé'); };
  $('#stSel').addEventListener('change', syncStat);
  const toggleSvc = () => { if (admin) $('#usvc').hidden = $('#urole').value !== 'agent'; };
  if (admin) { $('#urole').addEventListener('change', toggleSvc); toggleSvc(); }

  // Actions sur les tableaux
  document.addEventListener('click', e => {
    const b = e.target.closest('button[data-a]'); if (!b) return;
    const id = b.dataset.id, a = b.dataset.a;
    if (a === 'edit') { const f = $('#fEdit'); fill(f, { ...rows.get(id), rid: id }); $('#mEdit').showModal(); }
    if (a === 'stat') { const r = rows.get(id), f = $('#fStat'); fill(f, { rid: id, statut: r.statut, motif_report_refus: r.motif_report_refus, nouvelle_date: r.date_souhaitee }); syncStat(); $('#mStat').showModal(); }
    if (a === 'del' && confirm('Supprimer définitivement ce rendez-vous ?')) safe(async () => { const j = await post({ do: 'rdv_delete', rid: id }); toast(j.message); await Promise.all([loadList(), loadStats()]); });
    if (a === 'sedit') { const f = $$('#t-services form')[0]; fill(f, { sid: id, ...svcs.get(id) }); f.scrollIntoView({ behavior: 'smooth' }); }
    if (a === 'sdel' && confirm('Supprimer ce service ?')) safe(async () => { const j = await post({ do: 'service_delete', sid: id }); toast(j.message); await loadServices(); });
    if (a === 'uedit') { const f = $$('#t-users form')[0]; fill(f, { uid: id, ...users.get(id), mot_de_passe: '' }); toggleSvc(); f.scrollIntoView({ behavior: 'smooth' }); }
    if (a === 'udel' && confirm('Supprimer cet utilisateur ?')) safe(async () => { const j = await post({ do: 'user_delete', uid: id }); toast(j.message); await loadUsers(); });
  });

  // Après chaque enregistrement réussi : rechargement réel depuis MySQL
  document.addEventListener('done', e => safe(async () => {
    const d = e.detail.do;
    if (d === 'rdv_save' || d === 'rdv_statut') { $$('dialog[open]').forEach(x => x.close()); await Promise.all([loadList(), loadStats()]); }
    if (d === 'service_save') { clearForm(e.target); await loadServices(); }
    if (d === 'user_save') { clearForm(e.target); toggleSvc(); await loadUsers(); }
    if (d === 'entreprise_save') document.documentElement.style.setProperty('--c', e.detail.couleur);
  }));

  safe(async () => { await loadServices(); await Promise.all([loadList(), loadStats()]); });
}
})();
