<?php
session_start();

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['qr_code'])) {
    $qrCode = $_POST['qr_code'];

    if (!preg_match('/^\d{16}$/', $qrCode)) {
        echo json_encode(['success' => false, 'message' => 'Invalid QR code format.']);
        exit;
    }

    $pdo = new PDO("mysql:host=localhost;dbname=addwise", "root", "Qazqaz12#");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $stmt = $pdo->prepare("SELECT * FROM qr_codes WHERE code = ? AND assigned_to IS NULL AND is_active = 1");
    $stmt->execute([$qrCode]);
    $qrRecord = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($qrRecord) {
        $stmt = $pdo->prepare("UPDATE qr_codes SET assigned_to = ?, created_at = NOW() WHERE id = ?");
        $stmt->execute([$_SESSION['user_id'], $qrRecord['id']]);
        echo json_encode(['success' => true, 'message' => 'Device successfully added!']);
    } else {
        echo json_encode(['success' => false, 'message' => 'QR code not found or already assigned.']);
    }
}
?>
