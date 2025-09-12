<?php
// api/rsvp.php
declare(strict_types=1);
require __DIR__ . '/config.php';

// Sólo mismo origen
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$host   = $_SERVER['HTTP_HOST'] ?? '';
if ($origin && parse_url($origin, PHP_URL_HOST) !== $host) {
    json_out(['ok' => false, 'error' => 'CORS not allowed'], 403);
}

// Serve token
$action = $_GET['action'] ?? '';
if ($action === 'token') {
    // Genera y guarda CSRF en sesión
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    json_out(['csrf' => $_SESSION['csrf']]);
}

// Sólo POST para registrar
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_out(['ok' => false, 'error' => 'Method not allowed'], 405);
}

// CSRF
$csrf = $_POST['csrf'] ?? '';
if (empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $csrf)) {
    json_out(['ok' => false, 'error' => 'CSRF inválido. Recarga la página.'], 400);
}

// Campos
$name   = trim((string)($_POST['name']  ?? ''));
$email  = trim((string)($_POST['email'] ?? ''));
$source = trim((string)($_POST['source'] ?? ''));

// Validaciones simples
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    json_out(['ok' => false, 'error' => 'Email inválido.'], 422);
}
if ($name === '') $name = 'Suscriptor';

// Event date fijo (o puedes permitir override si lo envías)
$eventDate = '2025-11-01';

// Anti‑spam (honeypot opcional)
if (!empty($_POST['website'] ?? '')) {
    // Campo trampa relleno = bot
    json_out(['ok' => true]); // responder OK silencioso
}

// Inserta
try {
    $stmt = $pdo->prepare('
    INSERT INTO rsvps (name, email, source, event_date, ip_address, user_agent)
    VALUES (:name, :email, :source, :event_date, :ip, :ua)
    ON DUPLICATE KEY UPDATE
      name = VALUES(name),
      source = VALUES(source),
      user_agent = VALUES(user_agent)
  ');
    $stmt->execute([
        ':name'       => $name,
        ':email'      => mb_strtolower($email),
        ':source'     => $source ?: '/landing#form',
        ':event_date' => $eventDate,
        ':ip'         => ip_to_binary(get_client_ip()),
        ':ua'         => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255),
    ]);

    // (Opcional) notifica por mail
    // @mail('tucorreo@dominio.cl', 'Nuevo RSVP FFV', "Nombre: $name\nEmail: $email\n", "From: no-reply@{$_SERVER['HTTP_HOST']}\r\n");

    json_out(['ok' => true]);
} catch (Throwable $e) {
    // Si es duplicado, también respondemos ok (ya está inscrito)
    if ($e instanceof PDOException && $e->errorInfo[1] === 1062) {
        json_out(['ok' => true, 'dup' => true]);
    }
    json_out(['ok' => false, 'error' => 'No se pudo guardar.'], 500);
}
