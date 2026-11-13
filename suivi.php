<?php
require __DIR__ . '/config/db.php'; require __DIR__ . '/config/layout.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_ok()) json_out(['ok' => false, 'error' => 'Session invalide, rechargez la page.'], 403);
    $now = time(); $_SESSION['sv'] = array_filter($_SESSION['sv'] ?? [], fn($t) => $t > $now - 600);
    if (count($_SESSION['sv']) >= 20) json_out(['ok' => false, 'error' => 'Trop de recherches. Réessayez dans quelques minutes.'], 429);
    $_SESSION['sv'][] = $now;
    $code = strtoupper(trim($_POST['code'] ?? ''));
    $s = $pdo->prepare("SELECT r.code_suivi,r.nom,r.prenom,r.statut,r.date_souhaitee,r.motif_report_refus,r.date_creation,s.nom AS service
                        FROM rendez_vous r JOIN services s ON s.id=r.service_id WHERE r.code_suivi=?");
    $s->execute([$code]); $r = $s->fetch();
    if (!$r) json_out(['ok' => false, 'error' => 'Aucun rendez-vous ne correspond à ce code.'], 404);
    json_out(['ok' => true, 'rdv' => $r]);
}
page_head('Suivi de rendez-vous', 'suivi'); ?>
<section class="card glass pad narrow">
  <h1 class="grad u">Suivi de rendez-vous</h1>
  <form id="fSuivi" data-ajax method="post">
    <input type="hidden" name="do" value="suivi">
    <label class="field">Code de suivi<input name="code" required maxlength="30" placeholder="GEST_RDV-<?= date('Y') ?>-XXXX" value="<?= e($_GET['code'] ?? '') ?>"></label>
    <button class="btn" type="submit">Consulter le statut</button>
  </form>
  <div id="res" class="result" hidden></div>
</section>
<?php page_foot();
