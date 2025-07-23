<?php
// Include comprehensive protection
require_once 'protection.php';

// Additional admin-specific checks for delete operations
if ($_SESSION['role'] !== 'Admin' && $_SESSION['role'] !== 'SuperAdmin') {
    SecurityMiddleware::logSecurityEvent('Unauthorized delete user attempt', "User: {$_SESSION['user_id']}, Role: {$_SESSION['role']}", 'WARNING');
    http_response_code(403);
    die('Access denied');
}

session_start();

// Verify admin permissions
if (!isset($_SESSION['is_logged_in']) || $_SESSION['role'] !== 'Admin') {
    header("Location: index3.php");
    exit();
}

// Database connection
$host = 'localhost';
$dbname = 'addwise';
$username = 'root';
$password = '123456';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

$user_id = $_POST['user_id'];

try {
    // Begin transaction
    $pdo->beginTransaction();
    
    // 1. Delete related QR requests
    $stmt = $pdo->prepare("DELETE FROM qr_requests WHERE user_id = :user_id OR assigned_by = :user_id");
    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->execute();
    
    // 2. Remove QR code assignments
    $stmt = $pdo->prepare("UPDATE qr_codes SET assigned_to = NULL WHERE assigned_to = :user_id");
    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->execute();
    
    // 3. Delete the user
    $stmt = $pdo->prepare("DELETE FROM users WHERE id = :user_id");
    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->execute();
    
    // Commit transaction
    $pdo->commit();
    
    $_SESSION['success_message'] = "User deleted successfully";
} catch (PDOException $e) {
    $pdo->rollBack();
    $_SESSION['error_message'] = "Error deleting user: " . $e->getMessage();
}

header("Location: admin_dashboard.php");
exit();
?>
