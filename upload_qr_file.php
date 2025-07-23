<?php
// Include comprehensive protection
require_once 'protection.php';

// Additional user-specific checks for upload operations
if (!in_array($_SESSION['role'], ['User', 'Admin', 'SuperAdmin'])) {
    SecurityMiddleware::logSecurityEvent('Unauthorized upload QR attempt', "User: {$_SESSION['user_id']}, Role: {$_SESSION['role']}", 'WARNING');
    http_response_code(403);
    die('Access denied');
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require 'vendor/autoload.php';
use Zxing\QrReader;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['qr_image'])) {
    $fileTmp = $_FILES['qr_image']['tmp_name'];
    $qr = new QrReader($fileTmp);
    $qrCodeText = $qr->text();

    if ($qrCodeText) {
        if (preg_match('/\d{16}/', $qrCodeText, $matches)) {
            $qrCode = $matches[0];

            $pdo = new PDO("mysql:host=localhost;dbname=addwise", "root", "123456");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            $user_id = $_SESSION['user_id'];
            $stmt = $pdo->prepare("SELECT * FROM qr_codes WHERE code = ? AND assigned_to IS NULL");
            $stmt->execute([$qrCode]);
            $qrRecord = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($qrRecord) {
                $stmt = $pdo->prepare("UPDATE qr_codes SET assigned_to = ?, created_at = NOW() WHERE id = ?");
                $stmt->execute([$user_id, $qrRecord['id']]);
                echo "<script>alert('QR code successfully assigned!'); window.location.href='user_dashboard.php';</script>";
            } else {
                echo "<script>alert('QR code not found or already assigned.'); window.location.href='user_dashboard.php';</script>";
            }
        } else {
            echo "<script>alert('No valid 16-digit QR code found in the uploaded file.'); window.location.href='user_dashboard.php';</script>";
        }
    } else {
        echo "<script>alert('No valid QR code found in the uploaded file.'); window.location.href='user_dashboard.php';</script>";
    }
}
echo "<script>
    document.addEventListener('DOMContentLoaded', function() {
        Swal.fire({
            icon: 'success',
            title: 'Success!',
            text: 'QR code successfully assigned!',
        }).then(() => {
            window.location.href = 'user_dashboard.php';
        });
    });
</script>";

?>
