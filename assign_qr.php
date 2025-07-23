<?php
// Include comprehensive protection
require_once 'protection.php';

// Additional admin-specific checks for QR assignment
if ($_SESSION['role'] !== 'Admin' && $_SESSION['role'] !== 'SuperAdmin') {
    SecurityMiddleware::logSecurityEvent('Unauthorized QR assignment attempt', "User: {$_SESSION['user_id']}, Role: {$_SESSION['role']}", 'WARNING');
    http_response_code(403);
    die('Access denied');
}

session_start();

if (!isset($_SESSION['is_logged_in']) || $_SESSION['role'] !== 'Admin') {
    header("Location: index3.php");
    exit();
}

// Database connection
$host = 'localhost';
$dbname = 'addwise';
$username = 'root';
$password = '123456';

$conn = new mysqli($host, $username, $password, $dbname);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $request_id = $_POST['request_id'];
    $user_id = $_POST['user_id'];
    $qr_id = $_POST['qr_id'];
    $admin_id = $_SESSION['user_id'];

    $conn->begin_transaction();

    try {
        // Assign QR code to user
        $stmt1 = $conn->prepare("UPDATE qr_codes SET assigned_to = ? WHERE id = ?");
        $stmt1->bind_param("ii", $user_id, $qr_id);
        $stmt1->execute();

        // Update request status and assignment
        $stmt2 = $conn->prepare("UPDATE qr_requests SET status = 'approved', assigned_qr_id = ?, assigned_by = ? WHERE id = ?");
        $stmt2->bind_param("iii", $qr_id, $admin_id, $request_id);
        $stmt2->execute();

        $conn->commit();
        header("Location: admin_dashboard.php?success=1");
    } catch (Exception $e) {
        $conn->rollback();
        header("Location: admin_dashboard.php?error=1");
    }
} else {
    header("Location: admin_dashboard.php");
}
?>
