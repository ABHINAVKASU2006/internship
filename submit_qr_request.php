<?php
// Include comprehensive protection
require_once 'protection.php';

// Additional superadmin-specific checks for QR request submission
if ($_SESSION['role'] !== 'SuperAdmin') {
    SecurityMiddleware::logSecurityEvent('Unauthorized QR request submission attempt', "User: {$_SESSION['user_id']}, Role: {$_SESSION['role']}", 'WARNING');
    http_response_code(403);
    die('Access denied');
}

session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reason'])) {
    $user_id = $_SESSION['user_id'];
    $reason = trim($_POST['reason']);

    // DB config
    $host = 'localhost';
    $dbname = 'addwise';
    $username = 'root';
    $password = '123456';

    try {
        $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $pdo->beginTransaction();

        // Insert QR request
        $stmt = $pdo->prepare("INSERT INTO qr_requests (user_id, reason, status, requested_at) VALUES (?, ?, 'approved', NOW())");
        $stmt->execute([$user_id, $reason]);
        $request_id = $pdo->lastInsertId();

        // Generate QR content (customize as needed)
        $qrContent = "User ID: $user_id | Request ID: $request_id";

        // Generate QR code using phpqrcode library
        require_once 'phpqrcode/qrlib.php';
        ob_start();
        \QRcode::png($qrContent, null, QR_ECLEVEL_L, 4);
        $imageData = ob_get_contents();
        ob_end_clean();

        $imageBase64 = base64_encode($imageData);

        // Insert QR code
        $stmt = $pdo->prepare("INSERT INTO qr_codes (code, image_data, assigned_to) VALUES (?, ?, ?)");
        $stmt->execute([$qrContent, $imageBase64, $user_id]);
        $qr_id = $pdo->lastInsertId();

        // Update request with assigned QR ID
        $stmt = $pdo->prepare("UPDATE qr_requests SET assigned_qr_id = ? WHERE id = ?");
        $stmt->execute([$qr_id, $request_id]);

        $pdo->commit();

        echo "QR code generated and assigned successfully";

    } catch (Exception $e) {
        $pdo->rollBack();
        http_response_code(500);
        echo "Error: " . $e->getMessage();
    }
} else {
    http_response_code(400);
    echo "Invalid request";
}
