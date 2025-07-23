<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

session_start();
header('Content-Type: application/json');
require_once 'protection.php';

// Additional user-specific checks for location retrieval
if (!in_array($_SESSION['role'], ['User', 'Admin', 'SuperAdmin'])) {
    SecurityMiddleware::logSecurityEvent('Unauthorized location retrieval attempt', "User: {$_SESSION['user_id']}, Role: {$_SESSION['role']}", 'WARNING');
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Access denied']);
    exit;
}

if (!isset($_SESSION['is_logged_in']) || $_SESSION['role'] !== 'User') {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Unauthorized access']);
    exit;
}
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
    exit;
}

// Database connection
$host = 'localhost';
$dbname = 'addwise';
$username = 'root';
$password = '123456';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
} catch (PDOException $e) {
    error_log("Database connection failed: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Database connection failed']);
    exit;
}

// Get user's QR code locations
$user_id = $_SESSION['user_id'];
try {
    $stmt = $pdo->prepare("
        SELECT ql.qr_id, ql.latitude, ql.longitude, ql.location_name, qc.code as qr_code
        FROM qr_locations ql
        JOIN qr_codes qc ON ql.qr_id = qc.id
        WHERE qc.assigned_to = ?
        ORDER BY ql.updated_at DESC
    ");
    $stmt->execute([$user_id]);
    $locations = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(['success' => true, 'locations' => $locations]);
    exit;
} catch (PDOException $e) {
    error_log("Location retrieval error: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error retrieving locations']);
    exit;
}
?>