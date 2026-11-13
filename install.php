<?php
require __DIR__ . '/config/db.php'; require __DIR__ . '/config/layout.php';
$done = installed();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_ok()) json_out(['ok' => false, 'error' => 'Session invalide, rechargez la page.'], 403);
    if ($done) json_out(['ok' => false, 'error' => 'GEST_RDV est déjà installé.'], 403);
    $ent = trim($_POST['entreprise'] ?? ''); $nom = trim($_POST['nom'] ?? ''); $mail = trim($_POST['email'] ?? '');
    $pw = (string)($_POST['mot_de_passe'] ?? '');
    if ($ent === '' || mb_strlen($ent) > 150) json_out(['ok' => false, 'error' => "Nom de la structure requis."], 422);
    if ($nom === '') json_out(['ok' => false, 'error' => 'Nom de l’administrateur requis.'], 422);
    if (!filter_var($mail, FILTER_VALIDATE_EMAIL)) json_out(['ok' => false, 'error' => 'Email invalide.'], 422);
    if (strlen($pw) < 8) json_out(['ok' => false, 'error' => 'Mot de passe : 8 caractères minimum.'], 422);
    try {
        $pdo->beginTransaction();
        if ($pdo->query("SELECT COUNT(*) FROM entreprises")->fetchColumn() > 0)
            $pdo->prepare("UPDATE entreprises SET nom=? ORDER BY id LIMIT 1")->execute([$ent]);
        else
            $pdo->prepare("INSERT INTO entreprises (nom) VALUES (?)")->execute([$ent]);
        $pdo->prepare("INSERT INTO utilisateurs (nom,email,mot_de_passe,role) VALUES (?,?,?,'super_admin')")
            ->execute([$nom, $mail, password_hash($pw, PASSWORD_DEFAULT)]);
        $pdo->commit();
    } catch (PDOException $ex) { $pdo->rollBack(); json_out(['ok' => false, 'error' => 'Installation impossible : ' . ($ex->getCode() === '23000' ? 'email déjà utilisé.' : 'erreur base de données.')], 500); }
    json_out(['ok' => true, 'message' => 'Super Admin créé. Redirection vers la connexion…']);
}
page_head('Installation', 'install'); ?>
<section class="card glass pad narrow">
  <h1 class="grad">Installation</h1>
  <?php if ($done): ?>
    <p>GEST_RDV est déjà installé. Pour votre sécurité, supprimez le fichier <code>install.php</code> du serveur.</p>
    <a class="btn" href="login.php">Se connecter</a>
  <?php else: ?>
    <p class="mut">Créez votre structure et le premier compte Super Admin.</p>
    <form data-ajax data-redirect="login.php" method="post">
      <input type="hidden" name="do" value="install">
      <label class="field">Nom de la structure<input name="entreprise" required maxlength="150" placeholder="Ex. Clinique Sainte-Marie"></label>
      <label class="field">Votre nom<input name="nom" required maxlength="120"></label>
      <label class="field">Email de connexion<input type="email" name="email" required></label>
      <label class="field">Mot de passe (8 caractères min.)<input type="password" name="mot_de_passe" required minlength="8"></label>
      <button class="btn" type="submit">Créer le Super Admin</button>
    </form>
  <?php endif; ?>
</section>
<?php page_foot();
