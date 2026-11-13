<?php
require __DIR__ . '/config/db.php'; require __DIR__ . '/config/layout.php';
$u = user();
$act = $_GET['api'] ?? ($_POST['do'] ?? null);
if (!$u) {
    if ($act !== null) json_out(['ok' => false, 'error' => 'Session expirée, reconnectez-vous.'], 401);
    header('Location: login.php'); exit;
}
$admin = $u['role'] === 'super_admin';

function scope($u) { return $u['role'] === 'super_admin' ? ['', []] : [' AND r.service_id=?', [(int)$u['service_id']]]; }
function rdv_find($id, $w, $p) {
    global $pdo;
    $s = $pdo->prepare("SELECT r.* FROM rendez_vous r WHERE r.id=? $w"); $s->execute(array_merge([$id], $p));
    $r = $s->fetch(); if (!$r) json_out(['ok' => false, 'error' => 'Rendez-vous introuvable ou non autorisé.'], 404);
    return $r;
}
function fail($m, $c = 422) { json_out(['ok' => false, 'error' => $m], $c); }

if ($act !== null) {
    try {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && !csrf_ok()) fail('Session invalide, rechargez la page.', 403);
        if (in_array($act, ['users', 'service_save', 'service_delete', 'user_save', 'user_delete', 'entreprise_save'], true) && !$admin) fail('Accès réservé au Super Admin.', 403);
        [$w, $p] = scope($u);
        switch ($act) {
            case 'stats':
                $s = $pdo->prepare("SELECT COUNT(*) total, COALESCE(SUM(r.statut='En attente'),0) attente, COALESCE(SUM(r.statut='Validé'),0) valide,
                    COALESCE(SUM(r.statut='Refusé'),0) refuse, COALESCE(SUM(r.statut='Reporté'),0) reporte FROM rendez_vous r WHERE 1=1 $w");
                $s->execute($p); $r = array_map('intval', $s->fetch()); json_out(['ok' => true] + $r);

            case 'list':
                $q = trim($_GET['q'] ?? ''); $st = $_GET['statut'] ?? ''; $d = $_GET['date'] ?? '';
                if ($q !== '') { $l = '%' . addcslashes($q, '%_\\') . '%'; $w .= " AND (r.nom LIKE ? OR r.prenom LIKE ? OR r.telephone LIKE ? OR r.code_suivi LIKE ?)"; array_push($p, $l, $l, $l, $l); }
                if (in_array($st, STATUTS, true)) { $w .= " AND r.statut=?"; $p[] = $st; }
                if (valid_date($d)) { $w .= " AND r.date_souhaitee=?"; $p[] = $d; }
                $s = $pdo->prepare("SELECT r.*, s.nom AS service FROM rendez_vous r LEFT JOIN services s ON s.id=r.service_id WHERE 1=1 $w ORDER BY r.date_creation DESC, r.id DESC LIMIT 500");
                $s->execute($p); json_out(['ok' => true, 'rows' => $s->fetchAll()]);

            case 'services':
                json_out(['ok' => true, 'rows' => $pdo->query("SELECT s.*, (SELECT COUNT(*) FROM rendez_vous r WHERE r.service_id=s.id) AS nb FROM services s ORDER BY s.nom")->fetchAll()]);

            case 'users':
                json_out(['ok' => true, 'rows' => $pdo->query("SELECT u.id,u.nom,u.email,u.role,u.service_id,s.nom AS service FROM utilisateurs u LEFT JOIN services s ON s.id=u.service_id ORDER BY u.nom")->fetchAll()]);

            case 'rdv_save':
                $r = rdv_find((int)($_POST['rid'] ?? 0), $w, $p);
                if (!$admin) $_POST['service_id'] = $r['service_id'];
                [$d, $err] = clean_rdv($_POST, false); if ($err) fail($err);
                $c = $pdo->prepare("SELECT COUNT(*) FROM services WHERE id=?"); $c->execute([$d['service_id']]); if (!$c->fetchColumn()) fail('Service inconnu.');
                $pdo->prepare("UPDATE rendez_vous SET nom=?,prenom=?,telephone=?,email=?,service_id=?,date_souhaitee=?,motif=? WHERE id=?")
                    ->execute([$d['nom'], $d['prenom'], $d['telephone'], $d['email'], $d['service_id'], $d['date_souhaitee'], $d['motif'], $r['id']]);
                json_out(['ok' => true, 'message' => 'Rendez-vous modifié.']);

            case 'rdv_statut':
                $r = rdv_find((int)($_POST['rid'] ?? 0), $w, $p);
                $st = $_POST['statut'] ?? ''; if (!in_array($st, STATUTS, true)) fail('Statut invalide.');
                $m = trim($_POST['motif_report_refus'] ?? ''); $nd = $r['date_souhaitee'];
                if (($st === 'Reporté' || $st === 'Refusé') && $m === '') fail('Un motif est obligatoire pour un report ou un refus.');
                if ($st === 'Reporté') { $nd = $_POST['nouvelle_date'] ?? ''; if (!valid_date($nd)) fail('Nouvelle date requise pour un report.'); }
                if ($st !== 'Reporté' && $st !== 'Refusé') $m = null;
                $pdo->prepare("UPDATE rendez_vous SET statut=?, motif_report_refus=?, date_souhaitee=? WHERE id=?")->execute([$st, $m, $nd, $r['id']]);
                json_out(['ok' => true, 'message' => 'Statut mis à jour : ' . $st . '.']);

            case 'rdv_delete':
                $r = rdv_find((int)($_POST['rid'] ?? 0), $w, $p);
                $pdo->prepare("DELETE FROM rendez_vous WHERE id=?")->execute([$r['id']]);
                json_out(['ok' => true, 'message' => 'Rendez-vous supprimé.']);

            case 'service_save':
                $id = (int)($_POST['sid'] ?? 0); $n = trim($_POST['nom'] ?? ''); $ds = trim($_POST['description'] ?? '');
                if ($n === '' || mb_strlen($n) > 120 || mb_strlen($ds) > 500) fail('Nom requis (120 car. max), description 500 car. max.');
                if ($id) $pdo->prepare("UPDATE services SET nom=?,description=? WHERE id=?")->execute([$n, $ds, $id]);
                else $pdo->prepare("INSERT INTO services (nom,description) VALUES (?,?)")->execute([$n, $ds]);
                json_out(['ok' => true, 'message' => $id ? 'Service modifié.' : 'Service créé.']);

            case 'service_delete':
                try { $pdo->prepare("DELETE FROM services WHERE id=?")->execute([(int)($_POST['sid'] ?? 0)]); }
                catch (PDOException $ex) { fail('Suppression impossible : ce service contient des rendez-vous ou des utilisateurs.'); }
                json_out(['ok' => true, 'message' => 'Service supprimé.']);

            case 'user_save':
                $id = (int)($_POST['uid'] ?? 0); $n = trim($_POST['nom'] ?? ''); $m = trim($_POST['email'] ?? '');
                $role = $_POST['role'] ?? ''; $sid = (int)($_POST['service_id'] ?? 0); $pw = (string)($_POST['mot_de_passe'] ?? '');
                if ($n === '' || mb_strlen($n) > 120) fail('Nom requis.');
                if (!filter_var($m, FILTER_VALIDATE_EMAIL)) fail('Email invalide.');
                if (!in_array($role, ['super_admin', 'agent'], true)) fail('Rôle invalide.');
                if ($role === 'agent') { $c = $pdo->prepare("SELECT COUNT(*) FROM services WHERE id=?"); $c->execute([$sid]); if (!$c->fetchColumn()) fail('Un agent doit être rattaché à un service.'); } else $sid = null;
                if ($id && $id === (int)$u['id'] && $role !== 'super_admin') fail('Vous ne pouvez pas retirer votre propre rôle Super Admin.');
                if (!$id && strlen($pw) < 8) fail('Mot de passe : 8 caractères minimum.');
                if ($id && $pw !== '' && strlen($pw) < 8) fail('Mot de passe : 8 caractères minimum.');
                try {
                    if ($id) {
                        $pdo->prepare("UPDATE utilisateurs SET nom=?,email=?,role=?,service_id=? WHERE id=?")->execute([$n, $m, $role, $sid, $id]);
                        if ($pw !== '') $pdo->prepare("UPDATE utilisateurs SET mot_de_passe=? WHERE id=?")->execute([password_hash($pw, PASSWORD_DEFAULT), $id]);
                    } else $pdo->prepare("INSERT INTO utilisateurs (nom,email,mot_de_passe,role,service_id) VALUES (?,?,?,?,?)")->execute([$n, $m, password_hash($pw, PASSWORD_DEFAULT), $role, $sid]);
                } catch (PDOException $ex) { fail('Cet email est déjà utilisé.'); }
                json_out(['ok' => true, 'message' => $id ? 'Utilisateur modifié.' : 'Utilisateur créé.']);

            case 'user_delete':
                $id = (int)($_POST['uid'] ?? 0); if ($id === (int)$u['id']) fail('Vous ne pouvez pas supprimer votre propre compte.');
                $pdo->prepare("DELETE FROM utilisateurs WHERE id=?")->execute([$id]);
                json_out(['ok' => true, 'message' => 'Utilisateur supprimé.']);

            case 'entreprise_save':
                $n = trim($_POST['nom'] ?? ''); $a = trim($_POST['adresse'] ?? ''); $t = trim($_POST['telephone'] ?? '');
                $m = trim($_POST['email'] ?? ''); $c = trim($_POST['couleur'] ?? '');
                if ($n === '' || mb_strlen($n) > 150) fail('Nom de la structure requis.');
                if (mb_strlen($a) > 255 || mb_strlen($t) > 30) fail('Adresse ou téléphone trop long.');
                if ($m !== '' && !filter_var($m, FILTER_VALIDATE_EMAIL)) fail('Email invalide.');
                if (!preg_match('/^#[0-9a-fA-F]{6}$/', $c)) fail('Couleur invalide.');
                if ($pdo->query("SELECT COUNT(*) FROM entreprises")->fetchColumn() > 0)
                    $pdo->prepare("UPDATE entreprises SET nom=?,adresse=?,telephone=?,email=?,couleur=? ORDER BY id LIMIT 1")->execute([$n, $a, $t, $m, $c]);
                else $pdo->prepare("INSERT INTO entreprises (nom,adresse,telephone,email,couleur) VALUES (?,?,?,?,?)")->execute([$n, $a, $t, $m, $c]);
                json_out(['ok' => true, 'message' => 'Paramètres enregistrés.', 'couleur' => $c]);

            default: fail('Action inconnue.', 400);
        }
    } catch (PDOException $ex) { json_out(['ok' => false, 'error' => 'Erreur base de données.'], 500); }
}

$c = entreprise();
$svcName = '';
if ($u['service_id']) { $s = $pdo->prepare("SELECT nom FROM services WHERE id=?"); $s->execute([$u['service_id']]); $svcName = (string)$s->fetchColumn(); }
page_head('Tableau de bord', 'dashboard', 'data-admin="' . ($admin ? 1 : 0) . '"'); ?>
<section class="hero-sm">
  <h1 class="grad u">Tableau de bord</h1>
  <p class="mut">Bonjour <b><?= e($u['nom']) ?></b> — <?= $admin ? 'Super Admin (tous les services)' : 'Agent / Direction : ' . e($svcName) ?></p>
</section>
<div class="tabs glass">
  <button class="tab on" data-t="rdv">Rendez-vous</button>
  <?php if ($admin): ?><button class="tab" data-t="services">Services</button><button class="tab" data-t="users">Utilisateurs</button><button class="tab" data-t="ent">Paramètres</button><?php endif; ?>
</div>

<section id="t-rdv" class="pane on">
  <div class="stats">
    <div class="card glass stat"><span id="s-total">–</span>Total</div>
    <div class="card glass stat w"><span id="s-attente">–</span>En attente</div>
    <div class="card glass stat v"><span id="s-valide">–</span>Validés</div>
    <div class="card glass stat x"><span id="s-refuse">–</span>Refusés</div>
    <div class="card glass stat r"><span id="s-reporte">–</span>Reportés</div>
  </div>
  <div class="glass pad filters">
    <input id="fq" type="search" placeholder="Rechercher : nom, téléphone ou code">
    <select id="fs"><option value="">Tous les statuts</option><?php foreach (STATUTS as $s): ?><option><?= e($s) ?></option><?php endforeach; ?></select>
    <input id="fd" type="date" title="Date souhaitée">
    <button class="btn ghost" id="freset" type="button">Réinitialiser</button>
  </div>
  <div class="glass pad tw"><table>
    <thead><tr><th>Code</th><th>Demandeur</th><th>Service</th><th>Date</th><th>Statut</th><th>Actions</th></tr></thead>
    <tbody id="rows"></tbody></table>
    <p id="empty" class="mut" hidden>Aucun rendez-vous ne correspond à votre recherche.</p></div>
</section>

<?php if ($admin): ?>
<section id="t-services" class="pane">
  <div class="glass pad"><h3 class="u">Service / direction</h3>
    <form data-ajax method="post" class="two">
      <input type="hidden" name="do" value="service_save"><input type="hidden" name="sid">
      <label class="field">Nom<input name="nom" required maxlength="120"></label>
      <label class="field">Description<input name="description" maxlength="500"></label>
      <div class="row"><button class="btn" type="submit">Enregistrer</button><button class="btn ghost" type="button" data-reset>Nouveau</button></div>
    </form></div>
  <div class="glass pad tw"><table><thead><tr><th>Nom</th><th>Description</th><th>RDV</th><th>Actions</th></tr></thead><tbody id="srows"></tbody></table></div>
</section>

<section id="t-users" class="pane">
  <div class="glass pad"><h3 class="u">Compte utilisateur</h3>
    <form data-ajax method="post" class="two">
      <input type="hidden" name="do" value="user_save"><input type="hidden" name="uid">
      <label class="field">Nom<input name="nom" required maxlength="120"></label>
      <label class="field">Email<input type="email" name="email" required></label>
      <label class="field">Mot de passe <small class="mut">(laisser vide pour ne pas changer)</small><input type="password" name="mot_de_passe" minlength="8" autocomplete="new-password"></label>
      <label class="field">Rôle<select name="role" id="urole"><option value="agent">Agent / Direction</option><option value="super_admin">Super Admin</option></select></label>
      <label class="field" id="usvc">Service<select name="service_id" class="svc-opts"></select></label>
      <div class="row"><button class="btn" type="submit">Enregistrer</button><button class="btn ghost" type="button" data-reset>Nouveau</button></div>
    </form></div>
  <div class="glass pad tw"><table><thead><tr><th>Nom</th><th>Email</th><th>Rôle</th><th>Service</th><th>Actions</th></tr></thead><tbody id="urows"></tbody></table></div>
</section>

<section id="t-ent" class="pane">
  <div class="glass pad"><h3 class="u">Paramètres de la structure</h3>
    <form data-ajax method="post" class="two">
      <input type="hidden" name="do" value="entreprise_save">
      <label class="field">Nom<input name="nom" required maxlength="150" value="<?= e($c['nom']) ?>"></label>
      <label class="field">Adresse<input name="adresse" maxlength="255" value="<?= e($c['adresse']) ?>"></label>
      <label class="field">Téléphone<input name="telephone" maxlength="30" value="<?= e($c['telephone']) ?>"></label>
      <label class="field">Email<input type="email" name="email" maxlength="150" value="<?= e($c['email']) ?>"></label>
      <label class="field">Couleur principale<input type="color" name="couleur" value="<?= e($c['couleur']) ?>"></label>
      <div class="row"><button class="btn" type="submit">Enregistrer</button></div>
    </form></div>
</section>
<?php endif; ?>

<dialog id="mEdit" class="glass"><form data-ajax method="post" id="fEdit">
  <h3 class="u">Modifier le rendez-vous</h3>
  <input type="hidden" name="do" value="rdv_save"><input type="hidden" name="rid">
  <div class="two">
    <label class="field">Nom<input name="nom" required maxlength="80"></label>
    <label class="field">Prénom<input name="prenom" required maxlength="80"></label>
    <label class="field">Téléphone<input name="telephone" required maxlength="25"></label>
    <label class="field">Email<input type="email" name="email" required></label>
    <label class="field">Service<select name="service_id" class="svc-opts" <?= $admin ? '' : 'disabled' ?>></select></label>
    <label class="field">Date souhaitée<input type="date" name="date_souhaitee" required></label>
  </div>
  <label class="field">Motif<textarea name="motif" rows="3" required maxlength="2000"></textarea></label>
  <div class="row"><button class="btn" type="submit">Enregistrer</button><button class="btn ghost" type="button" data-close>Annuler</button></div>
</form></dialog>

<dialog id="mStat" class="glass"><form data-ajax method="post" id="fStat">
  <h3 class="u">Changer le statut</h3>
  <input type="hidden" name="do" value="rdv_statut"><input type="hidden" name="rid">
  <label class="field">Statut<select name="statut" id="stSel"><?php foreach (STATUTS as $s): ?><option><?= e($s) ?></option><?php endforeach; ?></select></label>
  <label class="field" id="stDate" hidden>Nouvelle date<input type="date" name="nouvelle_date"></label>
  <label class="field" id="stMotif" hidden>Motif<textarea name="motif_report_refus" rows="3" maxlength="1000"></textarea></label>
  <div class="row"><button class="btn" type="submit">Appliquer</button><button class="btn ghost" type="button" data-close>Annuler</button></div>
</form></dialog>
<?php page_foot();
