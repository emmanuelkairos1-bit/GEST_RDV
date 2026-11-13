<?php
require __DIR__ . '/config/db.php'; require __DIR__ . '/config/layout.php';
if (!installed()) { header('Location: install.php'); exit; }
$c = entreprise();
$services = $pdo->query("SELECT nom,description FROM services ORDER BY nom")->fetchAll();
$nbRdv = (int)$pdo->query("SELECT COUNT(*) FROM rendez_vous")->fetchColumn();
page_head('Accueil', 'index'); ?>
<section class="hero">
  <h1 class="logo-big grad">GEST_RDV</h1>
  <h2 class="typing" data-text="Gérez vos rendez-vous, simplement."></h2>
  <p class="mut">Une plateforme unique pour recevoir, suivre et traiter les demandes de rendez-vous de <b><?= e($c['nom']) ?></b>.</p>
  <div class="row"><a class="btn" href="demande.php">Demander un rendez-vous</a><a class="btn ghost" href="suivi.php">Suivre ma demande</a></div>
</section>
<section class="grid">
  <article class="card glass pad"><h3 class="u">Notre structure</h3>
    <p><b><?= e($c['nom']) ?></b></p>
    <?php if ($c['adresse']): ?><p class="mut">📍 <?= e($c['adresse']) ?></p><?php endif; ?>
    <?php if ($c['telephone']): ?><p class="mut">📞 <a href="tel:<?= e($c['telephone']) ?>"><?= e($c['telephone']) ?></a></p><?php endif; ?>
    <?php if ($c['email']): ?><p class="mut">✉️ <a href="mailto:<?= e($c['email']) ?>"><?= e($c['email']) ?></a></p><?php endif; ?>
  </article>
  <article class="card glass pad"><h3 class="u">En chiffres</h3>
    <p class="big"><?= $nbRdv ?></p><p class="mut">demande(s) de rendez-vous enregistrée(s)</p>
    <p class="big"><?= count($services) ?></p><p class="mut">service(s) / direction(s)</p>
  </article>
  <article class="card glass pad"><h3 class="u">Services</h3>
    <?php if (!$services): ?><p class="mut">Aucun service n’a encore été créé.</p><?php endif; ?>
    <?php foreach ($services as $s): ?><p><b><?= e($s['nom']) ?></b><?php if ($s['description']): ?><br><span class="mut"><?= e($s['description']) ?></span><?php endif; ?></p><?php endforeach; ?>
  </article>
</section>
<?php page_foot();
