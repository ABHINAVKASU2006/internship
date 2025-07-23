<?php
/**
 * Comprehensive Protection System
 * Include this file at the top of every PHP file for complete protection
 */
function rateLimit($limit = 10, $interval = 60) {
    $key = 'rate_limit_' . md5($_SERVER['REMOTE_ADDR'] . $_SERVER['REQUEST_URI']);
    
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = [
            'count' => 1,
            'time' => time()
        ];
    } else {
        if (time() - $_SESSION[$key]['time'] < $interval) {
            $_SESSION[$key]['count']++;
            if ($_SESSION[$key]['count'] > $limit) {
                http_response_code(429);
                echo json_encode(['success' => false, 'message' => 'Too many requests']);
                exit;
            }
        } else {
            $_SESSION[$key] = [
                'count' => 1,
                'time' => time()
            ];
        }
    }
}

// Call this at the top of sensitive endpoints
rateLimit();
// Prevent direct access to this file
if (basename($_SERVER['SCRIPT_NAME']) === 'protection.php') {
    http_response_code(403);
    die('Direct access not allowed');
}

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Define secure access constant
define('SECURE_ACCESS', true);

// Include security files
require_once 'security_middleware.php';
require_once 'router_protection.php';

// Initialize security
SecurityMiddleware::init();

// Initialize router protection
$router = new RouterProtection();

// Get current file name
$currentFile = basename($_SERVER['SCRIPT_NAME']);

// Define route categories
$publicFiles = [
    'index3.php', 'login.php', 'register.php', 'signup.php',
    'forgot_password.php', 'reset_password.php', 'reset_password_otp.php',
    'verify_otp.php', 'check_otp.php', 'mailer.php', 'otp_mailer.php',
    'index.html', 'index1.html', 'index2.html', 'room.html',
    'style.css', 'style2.css', 'style3.css'
];

$userFiles = [
    'user_dashboard.php', 'view_profile_users.php', 'edit_profile_users.php',
    'add_device.php', 'manual_qr_add.php', 'upload_qr_file.php',
    'save_location.php', 'get_qr_locations.php', 'stop_location_sharing.php'
];

$adminFiles = [
    'admin_dashboard.php', 'edit_user.php', 'delete_user.php',
    'assign_qr.php', 'generate_qr.php', 'whatsapp.php', 'email.php'
];

$superAdminFiles = [
    'superadmin_dashboard.php', 'superadmin_login.php', 'superadmin_logout.php',
    'delete_qr.php', 'submit_qr_request.php'
];

$logoutFiles = ['logout.php', 'superadmin_logout.php'];

// Check if current file is public
if (in_array($currentFile, $publicFiles)) {
    // Public files - no additional checks needed
    return;
}

// Check if current file is a logout file
if (in_array($currentFile, $logoutFiles)) {
    // Logout files - allow access
    return;
}

// Check authentication for all other files
if (!isset($_SESSION['is_logged_in']) || $_SESSION['is_logged_in'] !== true) {
    SecurityMiddleware::secureRedirect('index3.php');
}

// Check role-based access
if (in_array($currentFile, $userFiles)) {
    if (!in_array($_SESSION['role'], ['User', 'Admin', 'SuperAdmin'])) {
        SecurityMiddleware::logSecurityEvent('Unauthorized access attempt', "User: {$_SESSION['user_id']}, File: $currentFile", 'WARNING');
        SecurityMiddleware::secureRedirect('index3.php');
    }
}

if (in_array($currentFile, $adminFiles)) {
    if (!in_array($_SESSION['role'], ['Admin', 'SuperAdmin'])) {
        SecurityMiddleware::logSecurityEvent('Unauthorized admin access attempt', "User: {$_SESSION['user_id']}, File: $currentFile", 'WARNING');
        SecurityMiddleware::secureRedirect('index3.php');
    }
}

if (in_array($currentFile, $superAdminFiles)) {
    if ($_SESSION['role'] !== 'SuperAdmin') {
        SecurityMiddleware::logSecurityEvent('Unauthorized super admin access attempt', "User: {$_SESSION['user_id']}, File: $currentFile", 'WARNING');
        SecurityMiddleware::secureRedirect('index3.php');
    }
}

// Additional security checks for specific files
switch ($currentFile) {
    case 'delete_user.php':
    case 'delete_qr.php':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            die('Method not allowed');
        }
        if (!isset($_POST['csrf_token']) || !SecurityMiddleware::validateCSRFToken($_POST['csrf_token'])) {
            http_response_code(403);
            die('CSRF token validation failed');
        }
        break;
        
    case 'upload_qr_file.php':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            die('Method not allowed');
        }
        if (!isset($_POST['csrf_token']) || !SecurityMiddleware::validateCSRFToken($_POST['csrf_token'])) {
            http_response_code(403);
            die('CSRF token validation failed');
        }
        break;
        
    case 'save_location.php':
    case 'get_qr_locations.php':
    case 'stop_location_sharing.php':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            die('Method not allowed');
        }
        break;
}

// Rate limiting for sensitive operations
if (in_array($currentFile, ['login.php', 'register.php', 'forgot_password.php'])) {
    if (!SecurityMiddleware::checkRateLimit($currentFile, 5, 300)) { // 5 requests per 5 minutes
        http_response_code(429);
        die('Too many requests. Please wait before trying again.');
    }
}

// Log successful access
SecurityMiddleware::logSecurityEvent('Page accessed', "User: {$_SESSION['user_id']}, Role: {$_SESSION['role']}, File: $currentFile", 'INFO');

// Update session activity
$_SESSION['LAST_ACTIVITY'] = time();

// Prevent session fixation
if (!isset($_SESSION['created'])) {
    $_SESSION['created'] = time();
} else if (time() - $_SESSION['created'] > 1800) {
    session_regenerate_id(true);
    $_SESSION['created'] = time();
}


?> 