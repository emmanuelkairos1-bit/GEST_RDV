<?php
require __DIR__ . '/config/db.php'; require __DIR__ . '/config/layout.php';
if (!installed()) { header('Location: install.php'); exit; }
if (user()) { header('Location: dashboard.php'); exit; }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_ok()) json_out(['ok' => false, 'error' => 'Session invalide, rechargez la page.'], 403);
    $now = time(); $_SESSION['lf'] = array_filter($_SESSION['lf'] ?? [], fn($t) => $t > $now - 300);
    if (count($_SESSION['lf']) >= 5) json_out(['ok' => false, 'error' => 'Trop d’échecs. Réessayez dans 5 minutes.'], 429);
    $s = $pdo->prepare("SELECT id,mot_de_passe FROM utilisateurs WHERE email=?");
    $s->execute([trim($_POST['email'] ?? '')]); $u = $s->fetch();
    if (!$u || !password_verify((string)($_POST['mot_de_passe'] ?? ''), $u['mot_de_passe'])) {
        $_SESSION['lf'][] = $now; json_out(['ok' => false, 'error' => 'Email ou mot de passe incorrect.'], 401);
    }
    session_regenerate_id(true); $_SESSION['uid'] = (int)$u['id']; unset($_SESSION['lf']);
    json_out(['ok' => true, 'message' => 'Connexion réussie.']);
}
page_head('Connexion', 'login'); ?>
<section class="card glass pad narrow">
  <h1 class="grad u">Connexion</h1>
  <form data-ajax data-redirect="dashboard.php" method="post">
    <input type="hidden" name="do" value="login">
    <label class="field">Email<input type="email" name="email" required autocomplete="username"></label>
    <label class="field">Mot de passe<input type="password" name="mot_de_passe" required autocomplete="current-password"></label>
    <button class="btn" type="submit">Se connecter</button>
  </form>
</section>
<?php page_foot();
