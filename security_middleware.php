<?php
/**
 * Security Middleware
 * Provides comprehensive security functions for the application
 */

// Prevent direct access
if (!defined('SECURE_ACCESS')) {
    http_response_code(403);
    die('Direct access not allowed');
}

class SecurityMiddleware {
    
    /**
     * Initialize security for the application
     */
    public static function init() {
        // Start session if not already started
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // Set security headers
        self::setSecurityHeaders();
        
        // Generate CSRF token if not exists
        self::generateCSRFToken();
        
        // Check session security
        if (!self::checkSessionSecurity()) {
            self::secureRedirect('index3.php');
        }
        
        // Block suspicious requests
        self::blockSuspiciousRequests();
        
        // Prevent caching
        self::preventCaching();
    }
    
    /**
     * Set security headers
     */
    public static function setSecurityHeaders() {
        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: DENY");
        header("X-XSS-Protection: 1; mode=block");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' data:; font-src 'self' https://cdnjs.cloudflare.com;");
    }
    
    /**
     * Generate CSRF token
     */
    public static function generateCSRFToken() {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
    }
    
    /**
     * Validate CSRF token
     */
    public static function validateCSRFToken($token) {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }
    
    /**
     * Check session security
     */
    public static function checkSessionSecurity() {
        // Check session timeout (30 minutes)
        if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > 1800)) {
            session_unset();
            session_destroy();
            return false;
        }
        
        $_SESSION['LAST_ACTIVITY'] = time();
        
        // Regenerate session ID periodically
        if (!isset($_SESSION['created'])) {
            $_SESSION['created'] = time();
        } else if (time() - $_SESSION['created'] > 1800) {
            session_regenerate_id(true);
            $_SESSION['created'] = time();
        }
        
        return true;
    }
    
    /**
     * Block suspicious requests
     */
    public static function blockSuspiciousRequests() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $suspiciousPatterns = [
            'libwww-perl', 'wget', 'python', 'nikto', 'acunetix', 'havij',
            'sqlmap', 'nmap', 'curl', 'scan', 'crawler', 'bot'
        ];
        
        foreach ($suspiciousPatterns as $pattern) {
            if (stripos($userAgent, $pattern) !== false) {
                self::logSecurityEvent('Suspicious User Agent Blocked', $userAgent, 'WARNING');
                http_response_code(403);
                die('Access Denied');
            }
        }
        
        // Check for suspicious query parameters
        $suspiciousParams = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'script', 'javascript'];
        foreach ($_GET as $key => $value) {
            foreach ($suspiciousParams as $pattern) {
                if (stripos($value, $pattern) !== false) {
                    self::logSecurityEvent('Suspicious Query Parameter Blocked', "$key=$value", 'WARNING');
                    http_response_code(403);
                    die('Access Denied');
                }
            }
        }
    }
    
    /**
     * Prevent caching
     */
    public static function preventCaching() {
        header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
        header("Cache-Control: post-check=0, pre-check=0", false);
        header("Pragma: no-cache");
    }
    
    /**
     * Secure redirect
     */
    public static function secureRedirect($url, $statusCode = 302) {
        // Clear any output buffers
        while (ob_get_level()) {
            ob_end_clean();
        }
        
        // Set security headers
        self::setSecurityHeaders();
        
        // Redirect
        header("Location: $url", true, $statusCode);
        exit();
    }
    
    /**
     * Validate and sanitize input
     */
    public static function sanitizeInput($input, $type = 'string') {
        if (is_array($input)) {
            return array_map([self::class, 'sanitizeInput'], $input);
        }
        
        switch ($type) {
            case 'integer':
                return filter_var($input, FILTER_VALIDATE_INT);
            case 'email':
                return filter_var($input, FILTER_VALIDATE_EMAIL);
            case 'url':
                return filter_var($input, FILTER_VALIDATE_URL);
            case 'string':
            default:
                return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
        }
    }
    
    /**
     * Validate file upload
     */
    public static function validateFileUpload($file, $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'], $maxSize = 10485760) {
        if (!isset($file['error']) || is_array($file['error'])) {
            return false;
        }
        
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return false;
        }
        
        if ($file['size'] > $maxSize) {
            return false;
        }
        
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($file['tmp_name']);
        
        return in_array($mimeType, $allowedTypes);
    }
    
    /**
     * Check rate limiting
     */
    public static function checkRateLimit($action = 'default', $maxRequests = 10, $timeWindow = 60) {
        $currentTime = time();
        $ipAddress = $_SERVER['REMOTE_ADDR'];
        $key = "rate_limit_{$action}_{$ipAddress}";
        
        if (!isset($_SESSION[$key])) {
            $_SESSION[$key] = [
                'count' => 1,
                'first_request' => $currentTime
            ];
            return true;
        }
        
        $rateData = $_SESSION[$key];
        
        if ($currentTime - $rateData['first_request'] < $timeWindow) {
            $rateData['count']++;
            if ($rateData['count'] > $maxRequests) {
                return false;
            }
        } else {
            $rateData = [
                'count' => 1,
                'first_request' => $currentTime
            ];
        }
        
        $_SESSION[$key] = $rateData;
        return true;
    }
    
    /**
     * Log security events
     */
    public static function logSecurityEvent($event, $details = '', $level = 'INFO') {
        $logEntry = sprintf(
            "[%s] %s - %s - %s - IP: %s - User: %s\n",
            date('Y-m-d H:i:s'),
            $level,
            $event,
            $details,
            $_SERVER['REMOTE_ADDR'],
            $_SESSION['user_id'] ?? 'anonymous'
        );
        
        error_log($logEntry, 3, 'security.log');
    }
    
    /**
     * Validate user authentication
     */
    public static function requireAuth($requiredRole = null) {
        if (!isset($_SESSION['is_logged_in']) || $_SESSION['is_logged_in'] !== true) {
            self::logSecurityEvent('Authentication Required', 'User not logged in', 'WARNING');
            self::secureRedirect('index3.php');
        }
        
        if ($requiredRole !== null) {
            $userRole = $_SESSION['role'] ?? '';
            
            switch ($requiredRole) {
                case 'Admin':
                    if (!in_array($userRole, ['Admin', 'SuperAdmin'])) {
                        self::logSecurityEvent('Insufficient Permissions', "Required: $requiredRole, User: $userRole", 'WARNING');
                        self::secureRedirect('index3.php');
                    }
                    break;
                case 'SuperAdmin':
                    if ($userRole !== 'SuperAdmin') {
                        self::logSecurityEvent('Insufficient Permissions', "Required: $requiredRole, User: $userRole", 'WARNING');
                        self::secureRedirect('index3.php');
                    }
                    break;
                case 'User':
                    if (!in_array($userRole, ['User', 'Admin', 'SuperAdmin'])) {
                        self::logSecurityEvent('Insufficient Permissions', "Required: $requiredRole, User: $userRole", 'WARNING');
                        self::secureRedirect('index3.php');
                    }
                    break;
            }
        }
    }
    
    /**
     * Secure database connection
     */
    public static function secureDatabaseConnection($host, $dbname, $username, $password) {
        try {
            $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
            return $pdo;
        } catch (PDOException $e) {
            self::logSecurityEvent('Database Connection Failed', $e->getMessage(), 'ERROR');
            return false;
        }
    }
    
    /**
     * Validate POST request with CSRF protection
     */
    public static function validatePOSTRequest() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            die('Method Not Allowed');
        }
        
        if (!isset($_POST['csrf_token']) || !self::validateCSRFToken($_POST['csrf_token'])) {
            self::logSecurityEvent('CSRF Token Validation Failed', 'Invalid or missing CSRF token', 'WARNING');
            http_response_code(403);
            die('CSRF token validation failed');
        }
        
        // Check rate limiting
        if (!self::checkRateLimit('post_request', 10, 60)) {
            self::logSecurityEvent('Rate Limit Exceeded', 'Too many POST requests', 'WARNING');
            http_response_code(429);
            die('Too many requests. Please wait before trying again.');
        }
    }
}

// Initialize security middleware
SecurityMiddleware::init();
?> 