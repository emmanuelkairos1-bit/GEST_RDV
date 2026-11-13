<?php
function page_head($title, $page, $attrs = '') {
    $c = entreprise(); $u = user();
    $items = [['index.php', 'Accueil', 'index'], ['demande.php', 'Demande de RDV', 'demande'], ['suivi.php', 'Suivi de RDV', 'suivi']];
    $items[] = $u ? ['dashboard.php', 'Tableau de bord', 'dashboard'] : ['login.php', 'Connexion', 'login'];
?>
<!DOCTYPE html>
<html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf" content="<?= e(csrf()) ?>">
<title><?= e($title) ?> — GEST_RDV</title>
<link rel="stylesheet" href="assets/css/style.css">
<style>:root{--c:<?= e($c['couleur']) ?>}</style>
</head>
<body data-page="<?= e($page) ?>" <?= $attrs ?>>
<div class="blob b1"></div><div class="blob b2"></div><div class="blob b3"></div>
<div id="bar"></div>
<header class="nav glass">
  <a class="logo" href="index.php">GEST_RDV</a>
  <button id="burger" aria-label="Menu">☰</button>
  <nav id="menu">
    <?php foreach ($items as $i): ?><a href="<?= $i[0] ?>" class="<?= $page === $i[2] ? 'active' : '' ?>"><?= e($i[1]) ?></a><?php endforeach; ?>
    <?php if ($u): ?><a href="logout.php" class="out">Déconnexion</a><?php endif; ?>
  </nav>
</header>
<main class="wrap">
<?php }

function page_foot() { $c = entreprise(); ?>
</main>
<footer>© <?= date('Y') ?> <?= e($c['nom']) ?> — propulsé par <b class="grad">GEST_RDV</b></footer>
<div id="toasts"></div>
<script src="assets/js/main.js"></script>
</body></html>
<?php }
