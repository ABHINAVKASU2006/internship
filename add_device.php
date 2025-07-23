<?php
session_start();
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['qr_code'])) {
    echo json_encode(['success' => false, 'message' => 'Invalid request']);
    exit;
}

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Session expired']);
    exit;
}

// Extract and validate QR code
$qr_code = $_POST['qr_code'];
$extractedCode = '';

if (preg_match('/\d{16}/', $qr_code, $matches)) {
    $extractedCode = $matches[0];
} elseif (strpos($qr_code, 'code=') !== false) {
    parse_str(parse_url($qr_code, PHP_URL_QUERY), $params);
    $extractedCode = $params['code'] ?? '';
}

if (strlen($extractedCode) !== 16 || !ctype_digit($extractedCode)) {
    echo json_encode(['success' => false, 'message' => 'Invalid QR format']);
    exit;
}

// Database connection
try {
    $pdo = new PDO("mysql:host=localhost;dbname=addwise", 'root', 'Qazqaz12#');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    $pdo->beginTransaction();
    
    $stmt = $pdo->prepare("
        UPDATE qr_codes 
        SET assigned_to = :user_id 
        WHERE code = :code AND assigned_to IS NULL
    ");
    $stmt->execute([
        ':user_id' => $_SESSION['user_id'],
        ':code' => $extractedCode
    ]);
    
    if ($stmt->rowCount() > 0) {
        $pdo->commit();
        echo json_encode([
            'success' => true,
            'code' => $extractedCode,
            'message' => 'QR code assigned successfully'
        ]);
    } else {
        $pdo->rollBack();
        echo json_encode([
            'success' => false,
            'message' => 'QR code not available or already assigned'
        ]);
    }
} catch (PDOException $e) {
    $pdo->rollBack();
    echo json_encode([
        'success' => false,
        'message' => 'Database error: ' . $e->getMessage()
    ]);
}
?>