<?php
/**
 * Security Configuration File
 * Include this file at the beginning of all PHP files for consistent security
 */

// Prevent direct access to this file
if (!defined('SECURE_ACCESS')) {
    http_response_code(403);
    die('Direct access not allowed');
}

// Security headers
function setSecurityHeaders() {
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: DENY");
    header("X-XSS-Protection: 1; mode=block");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' data:; font-src 'self' https://cdnjs.cloudflare.com;");
}

// CSRF Protection
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Input validation and sanitization
function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

function validateInteger($value) {
    return filter_var($value, FILTER_VALIDATE_INT);
}

// Rate limiting
function checkRateLimit($action = 'default', $max_requests = 10, $time_window = 60) {
    $current_time = time();
    $ip_address = $_SERVER['REMOTE_ADDR'];
    $key = "rate_limit_{$action}_{$ip_address}";
    
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = [
            'count' => 1,
            'first_request' => $current_time
        ];
        return true;
    }
    
    $rate_data = $_SESSION[$key];
    
    if ($current_time - $rate_data['first_request'] < $time_window) {
        $rate_data['count']++;
        if ($rate_data['count'] > $max_requests) {
            return false;
        }
    } else {
        $rate_data = [
            'count' => 1,
            'first_request' => $current_time
        ];
    }
    
    $_SESSION[$key] = $rate_data;
    return true;
}

// Session security
function secureSession() {
    // Regenerate session ID periodically
    if (!isset($_SESSION['created'])) {
        $_SESSION['created'] = time();
    } else if (time() - $_SESSION['created'] > 1800) {
        session_regenerate_id(true);
        $_SESSION['created'] = time();
    }
    
    // Update last activity
    $_SESSION['LAST_ACTIVITY'] = time();
    
    // Check session timeout (30 minutes)
    if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > 1800)) {
        session_unset();
        session_destroy();
        return false;
    }
    
    return true;
}

// Database security
function secureDatabaseConnection($host, $dbname, $username, $password) {
    try {
        $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
        return $pdo;
    } catch (PDOException $e) {
        error_log("Database connection failed: " . $e->getMessage());
        return false;
    }
}

// File upload security
function validateFileUpload($file, $allowed_types = ['image/jpeg', 'image/png', 'image/gif'], $max_size = 10485760) {
    if (!isset($file['error']) || is_array($file['error'])) {
        return false;
    }
    
    if ($file['error'] !== UPLOAD_ERR_OK) {
        return false;
    }
    
    if ($file['size'] > $max_size) {
        return false;
    }
    
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime_type = $finfo->file($file['tmp_name']);
    
    if (!in_array($mime_type, $allowed_types)) {
        return false;
    }
    
    return true;
}

// Logging
function logSecurityEvent($event, $details = '') {
    $log_entry = date('Y-m-d H:i:s') . " - {$event} - {$details} - IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
    error_log($log_entry, 3, 'security.log');
}

// Prevent caching
function preventCaching() {
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Cache-Control: post-check=0, pre-check=0", false);
    header("Pragma: no-cache");
}

// Initialize security
setSecurityHeaders();
preventCaching();
generateCSRFToken();

// Check if session is secure
if (!secureSession()) {
    header("Location: index3.php");
    exit();
}
?> 