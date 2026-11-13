<?php
// === CONFIGURATION MYSQL (XAMPP par défaut : root, sans mot de passe) ===
$DB = ['host' => 'localhost', 'name' => 'gest_rdv', 'user' => 'root', 'pass' => ''];

const STATUTS = ['En attente', 'Validé', 'Reporté', 'Refusé'];

try {
    $pdo = new PDO(
        "mysql:host={$DB['host']};dbname={$DB['name']};charset=utf8mb4",
        $DB['user'], $DB['pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]
    );
} catch (PDOException $e) {
    http_response_code(500);
    die('Connexion MySQL impossible. Vérifiez config/db.php et importez database/base.sql dans phpMyAdmin.');
}

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax']);
    session_start();
}

function e($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function json_out($d, $c = 200) {
    http_response_code($c);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($d, JSON_UNESCAPED_UNICODE);
    exit;
}

function csrf() { if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16)); return $_SESSION['csrf']; }
function csrf_ok() { return isset($_POST['csrf'], $_SESSION['csrf']) && hash_equals($_SESSION['csrf'], (string)$_POST['csrf']); }

function valid_date($d) { $x = DateTime::createFromFormat('Y-m-d', (string)$d); return $x && $x->format('Y-m-d') === $d; }

function entreprise() {
    global $pdo; static $c = null;
    if ($c === null) {
        try { $c = $pdo->query("SELECT * FROM entreprises ORDER BY id LIMIT 1")->fetch() ?: false; }
        catch (PDOException $e) { die('Base non importée : importez database/base.sql dans phpMyAdmin.'); }
    }
    return $c ?: ['nom' => 'Ma structure', 'adresse' => '', 'telephone' => '', 'email' => '', 'couleur' => '#6c5ce7'];
}

function installed() {
    global $pdo;
    try { return (int)$pdo->query("SELECT COUNT(*) FROM utilisateurs WHERE role='super_admin'")->fetchColumn() > 0; }
    catch (PDOException $e) { die('Base non importée : importez database/base.sql dans phpMyAdmin.'); }
}

function user() {
    global $pdo; static $u = false;
    if ($u !== false) return $u;
    $u = null;
    if (!empty($_SESSION['uid'])) {
        $s = $pdo->prepare("SELECT id,nom,email,role,service_id FROM utilisateurs WHERE id=?");
        $s->execute([$_SESSION['uid']]);
        $u = $s->fetch() ?: null;
    }
    return $u;
}

function gen_code() {
    $a = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; $s = '';
    for ($i = 0; $i < 4; $i++) $s .= $a[random_int(0, 31)];
    return 'GEST_RDV-' . date('Y') . '-' . $s;
}

function clean_rdv($in, $future) {
    $d = [];
    foreach (['nom', 'prenom', 'telephone', 'email', 'motif'] as $k) $d[$k] = trim((string)($in[$k] ?? ''));
    $d['service_id'] = (int)($in['service_id'] ?? 0);
    $d['date_souhaitee'] = trim((string)($in['date_souhaitee'] ?? ''));
    if ($d['nom'] === '' || $d['prenom'] === '' || mb_strlen($d['nom']) > 80 || mb_strlen($d['prenom']) > 80) return [null, 'Nom et prénom requis (80 caractères maximum).'];
    if (!preg_match('/^[0-9+\s().-]{6,25}$/', $d['telephone'])) return [null, 'Numéro de téléphone invalide.'];
    if (!filter_var($d['email'], FILTER_VALIDATE_EMAIL) || strlen($d['email']) > 150) return [null, 'Adresse email invalide.'];
    if (!valid_date($d['date_souhaitee']) || ($future && $d['date_souhaitee'] < date('Y-m-d'))) return [null, 'Date souhaitée invalide (elle ne peut pas être passée).'];
    if ($d['motif'] === '' || mb_strlen($d['motif']) > 2000) return [null, 'Motif requis (2000 caractères maximum).'];
    return [$d, null];
}
