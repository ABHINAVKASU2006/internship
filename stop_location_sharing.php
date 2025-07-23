<?php
// Additional user-specific checks for location sharing control
if (!in_array($_SESSION['role'], ['User', 'Admin', 'SuperAdmin'])) {
    SecurityMiddleware::logSecurityEvent('Unauthorized location sharing control attempt', "User: {$_SESSION['user_id']}, Role: {$_SESSION['role']}", 'WARNING');
    http_response_code(403);
    die(json_encode(['success' => false, 'message' => 'Access denied']));
}

session_start();

// Security check
if (!isset($_SESSION['is_logged_in']) || $_SESSION['role'] !== 'User') {
    http_response_code(403);
    die(json_encode(['success' => false, 'message' => 'Unauthorized access']));
}

// CSRF Protection
if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    http_response_code(403);
    die(json_encode(['success' => false, 'message' => 'CSRF token validation failed']));
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
    die(json_encode(['success' => false, 'message' => 'Database connection failed']));
}

// Validate input
$qr_id = filter_var($_POST['qr_id'], FILTER_VALIDATE_INT);
if (!$qr_id) {
    die(json_encode(['success' => false, 'message' => 'Invalid QR ID']));
}

// Check if QR code belongs to the user
$user_id = $_SESSION['user_id'];
try {
    $stmt = $pdo->prepare("SELECT id FROM qr_codes WHERE id = ? AND assigned_to = ?");
    $stmt->execute([$qr_id, $user_id]);
    if (!$stmt->fetch()) {
        die(json_encode(['success' => false, 'message' => 'QR code not found or not assigned to you']));
    }
} catch (PDOException $e) {
    error_log("QR code validation error: " . $e->getMessage());
    die(json_encode(['success' => false, 'message' => 'Error validating QR code']));
}

// Remove location from database
try {
    $stmt = $pdo->prepare("DELETE FROM qr_locations WHERE qr_id = ?");
    $stmt->execute([$qr_id]);
    
    echo json_encode(['success' => true, 'message' => 'Location sharing stopped successfully']);
} catch (PDOException $e) {
    error_log("Location removal error: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error stopping location sharing']);
}
?> 