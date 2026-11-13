<?php
require __DIR__ . '/config/db.php'; require __DIR__ . '/config/layout.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_ok()) json_out(['ok' => false, 'error' => 'Session invalide, rechargez la page.'], 403);
    [$d, $err] = clean_rdv($_POST, true);
    if ($err) json_out(['ok' => false, 'error' => $err], 422);
    $s = $pdo->prepare("SELECT COUNT(*) FROM services WHERE id=?"); $s->execute([$d['service_id']]);
    if (!$s->fetchColumn()) json_out(['ok' => false, 'error' => 'Service inconnu.'], 422);
    for ($i = 0; $i < 10; $i++) {
        $code = gen_code();
        try {
            $pdo->prepare("INSERT INTO rendez_vous (code_suivi,nom,prenom,telephone,email,service_id,date_souhaitee,motif) VALUES (?,?,?,?,?,?,?,?)")
                ->execute([$code, $d['nom'], $d['prenom'], $d['telephone'], $d['email'], $d['service_id'], $d['date_souhaitee'], $d['motif']]);
            json_out(['ok' => true, 'code' => $code, 'message' => 'Demande enregistrée.']);
        } catch (PDOException $ex) { if ($ex->getCode() !== '23000') json_out(['ok' => false, 'error' => 'Erreur base de données.'], 500); }
    }
    json_out(['ok' => false, 'error' => 'Impossible de générer un code, réessayez.'], 500);
}
$services = $pdo->query("SELECT id,nom FROM services ORDER BY nom")->fetchAll();
page_head('Demande de rendez-vous', 'demande'); ?>
<section class="card glass pad narrow">
  <h1 class="grad u">Demande de rendez-vous</h1>
  <?php if (!$services): ?><p class="mut">Aucun service n’est disponible pour le moment. Revenez plus tard.</p>
  <?php else: ?>
  <form id="fDemande" data-ajax method="post">
    <input type="hidden" name="do" value="demande">
    <div class="two">
      <label class="field">Nom<input name="nom" required maxlength="80"></label>
      <label class="field">Prénom<input name="prenom" required maxlength="80"></label>
      <label class="field">Téléphone<input name="telephone" type="tel" required maxlength="25"></label>
      <label class="field">Email<input name="email" type="email" required maxlength="150"></label>
      <label class="field">Service<select name="service_id" required><option value="">Choisir…</option>
        <?php foreach ($services as $s): ?><option value="<?= (int)$s['id'] ?>"><?= e($s['nom']) ?></option><?php endforeach; ?></select></label>
      <label class="field">Date souhaitée<input type="date" name="date_souhaitee" required min="<?= date('Y-m-d') ?>"></label>
    </div>
    <label class="field">Motif<textarea name="motif" rows="4" required maxlength="2000"></textarea></label>
    <button class="btn" type="submit">Envoyer la demande</button>
  </form>
  <div id="res" class="result" hidden></div>
  <?php endif; ?>
</section>
<?php page_foot();
