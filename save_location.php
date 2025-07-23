<?php
// Additional user-specific checks for location saving
session_start();
if (!in_array($_SESSION['role'], ['User', 'Admin', 'SuperAdmin'])) {
    SecurityMiddleware::logSecurityEvent('Unauthorized location save attempt', "User: {$_SESSION['user_id']}, Role: {$_SESSION['role']}", 'WARNING');
    http_response_code(403);
    die(json_encode(['success' => false, 'message' => 'Access denied']));
}



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
$latitude = filter_var($_POST['latitude'], FILTER_VALIDATE_FLOAT);
$longitude = filter_var($_POST['longitude'], FILTER_VALIDATE_FLOAT);
$location_name = trim($_POST['location_name'] ?? '');

if (!$qr_id || $latitude === false || $longitude === false) {
    die(json_encode(['success' => false, 'message' => 'Invalid input parameters']));
}

// Validate latitude and longitude ranges
if ($latitude < -90 || $latitude > 90 || $longitude < -180 || $longitude > 180) {
    die(json_encode(['success' => false, 'message' => 'Invalid latitude or longitude values']));
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

// Save or update location
try {
    // Check if location already exists
    $stmt = $pdo->prepare("SELECT id FROM qr_locations WHERE qr_id = ?");
    $stmt->execute([$qr_id]);
    
    if ($stmt->fetch()) {
        // Update existing location
        $stmt = $pdo->prepare("UPDATE qr_locations SET latitude = ?, longitude = ?, location_name = ?, updated_at = NOW() WHERE qr_id = ?");
        $stmt->execute([$latitude, $longitude, $location_name, $qr_id]);
    } else {
        // Insert new location
        $stmt = $pdo->prepare("INSERT INTO qr_locations (qr_id, latitude, longitude, location_name, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())");
        $stmt->execute([$qr_id, $latitude, $longitude, $location_name]);
    }
    
    echo json_encode(['success' => true, 'message' => 'Location saved successfully']);
} catch (PDOException $e) {
    error_log("Location save error: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error saving location']);
}
?> 