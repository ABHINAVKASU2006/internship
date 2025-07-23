<?php
// Include comprehensive protection
require_once 'protection.php';

// Additional superadmin-specific checks for delete QR operations
if ($_SESSION['role'] !== 'SuperAdmin') {
    SecurityMiddleware::logSecurityEvent('Unauthorized delete QR attempt', "User: {$_SESSION['user_id']}, Role: {$_SESSION['role']}", 'WARNING');
    http_response_code(403);
    die('Access denied');
}

session_start();

// Verify user is logged in
if (!isset($_SESSION['is_logged_in']) || $_SESSION['role'] !== 'User') {
    http_response_code(403);
    echo "Access denied";
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
    http_response_code(500);
    echo "Database connection failed: " . $e->getMessage();
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['qr_id'])) {
    $qr_id = $_POST['qr_id'];
    $user_id = $_SESSION['user_id'];
    
    try {
        // Begin transaction
        $pdo->beginTransaction();
        
        // First, verify this QR code belongs to the current user
        $stmt = $pdo->prepare("
            SELECT q.id, q.assigned_to, r.id as request_id 
            FROM qr_codes q
            JOIN qr_requests r ON q.id = r.assigned_qr_id
            WHERE q.id = ? AND q.assigned_to = ? AND r.user_id = ?
        ");
        $stmt->execute([$qr_id, $user_id, $user_id]);
        $qr_data = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$qr_data) {
            throw new Exception("QR code not found or access denied");
        }
        
        // Option 1: Reset the request status to 'pending' and remove assignment
        $stmt = $pdo->prepare("
            UPDATE qr_requests 
            SET assigned_qr_id = NULL, status = 'pending' 
            WHERE id = ?
        ");
        $stmt->execute([$qr_data['request_id']]);
        
        // Option 2: Alternative - Delete the request entirely (uncomment if preferred)
        // $stmt = $pdo->prepare("DELETE FROM qr_requests WHERE id = ?");
        // $stmt->execute([$qr_data['request_id']]);
        
        // Reset QR code assignment
        $stmt = $pdo->prepare("UPDATE qr_codes SET assigned_to = NULL WHERE id = ?");
        $stmt->execute([$qr_id]);
        
        // Commit transaction
        $pdo->commit();
        
        echo "QR code deleted successfully";
        
    } catch (Exception $e) {
        $pdo->rollBack();
        http_response_code(500);
        echo "Error deleting QR code: " . $e->getMessage();
    }
} else {
    http_response_code(400);
    echo "Invalid request";
}
?>
