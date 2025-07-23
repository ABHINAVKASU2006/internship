<?php
/**
 * Router Protection System
 * Handles URL routing, access control, and security validation
 */

class RouterProtection {
    private $allowedRoutes = [];
    private $protectedRoutes = [];
    private $adminRoutes = [];
    private $userRoutes = [];
    private $superAdminRoutes = [];
    
    public function __construct() {
        $this->initializeRoutes();
    }
    
    /**
     * Initialize allowed routes and their access levels
     */
    private function initializeRoutes() {
        // Public routes (no authentication required)
        $this->allowedRoutes = [
            'index3.php',
            'login.php',
            'register.php',
            'forgot_password.php',
            'reset_password.php',
            'verify_otp.php',
            'check_otp.php',
            'reset_password_otp.php'
        ];
        
        // Protected routes (require authentication)
        $this->protectedRoutes = [
            'user_dashboard.php',
            'admin_dashboard.php',
            'superadmin_dashboard.php',
            'view_profile_users.php',
            'edit_profile_users.php',
            'edit_user.php',
            'delete_user.php',
            'add_device.php',
            'manual_qr_add.php',
            'upload_qr_file.php',
            'whatsapp.php',
            'email.php',
            'logout.php',
            'superadmin_logout.php'
        ];
        
        // Admin-only routes
        $this->adminRoutes = [
            'admin_dashboard.php',
            'edit_user.php',
            'delete_user.php',
            'assign_qr.php',
            'generate_qr.php'
        ];
        
        // User-only routes
        $this->userRoutes = [
            'user_dashboard.php',
            'view_profile_users.php',
            'edit_profile_users.php',
            'add_device.php',
            'manual_qr_add.php',
            'upload_qr_file.php'
        ];
        
        // Super Admin-only routes
        $this->superAdminRoutes = [
            'superadmin_dashboard.php',
            'generate_qr.php',
            'assign_qr.php',
            'delete_qr.php'
        ];
    }
    
    /**
     * Check if current request is allowed
     */
    public function isAllowedRequest() {
        $currentFile = basename($_SERVER['SCRIPT_NAME']);
        
        // Check if it's a public route
        if (in_array($currentFile, $this->allowedRoutes)) {
            return true;
        }
        
        // Check if it's a protected route
        if (in_array($currentFile, $this->protectedRoutes)) {
            return $this->isAuthenticated();
        }
        
        // Block access to unknown files
        return false;
    }
    
    /**
     * Check if user is authenticated
     */
    public function isAuthenticated() {
        return isset($_SESSION['is_logged_in']) && $_SESSION['is_logged_in'] === true;
    }
    
    /**
     * Check if user has required role
     */
    public function hasRole($requiredRole) {
        if (!$this->isAuthenticated()) {
            return false;
        }
        
        $userRole = $_SESSION['role'] ?? '';
        
        switch ($requiredRole) {
            case 'Admin':
                return in_array($userRole, ['Admin', 'SuperAdmin']);
            case 'SuperAdmin':
                return $userRole === 'SuperAdmin';
            case 'User':
                return in_array($userRole, ['User', 'Admin', 'SuperAdmin']);
            default:
                return false;
        }
    }
    
    /**
     * Check if user can access current route
     */
    public function canAccessRoute() {
        $currentFile = basename($_SERVER['SCRIPT_NAME']);
        
        // Check Super Admin routes
        if (in_array($currentFile, $this->superAdminRoutes)) {
            return $this->hasRole('SuperAdmin');
        }
        
        // Check Admin routes
        if (in_array($currentFile, $this->adminRoutes)) {
            return $this->hasRole('Admin');
        }
        
        // Check User routes
        if (in_array($currentFile, $this->userRoutes)) {
            return $this->hasRole('User');
        }
        
        // Check protected routes
        if (in_array($currentFile, $this->protectedRoutes)) {
            return $this->isAuthenticated();
        }
        
        return false;
    }
    
    /**
     * Validate and sanitize input parameters
     */
    public function validateInput($input, $type = 'string') {
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
    public function validateFileUpload($file, $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'], $maxSize = 10485760) {
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
    public function checkRateLimit($action = 'default', $maxRequests = 10, $timeWindow = 60) {
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
    public function logSecurityEvent($event, $details = '', $level = 'INFO') {
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
     * Redirect with security headers
     */
    public function secureRedirect($url, $statusCode = 302) {
        // Clear any output buffers
        while (ob_get_level()) {
            ob_end_clean();
        }
        
        // Set security headers
        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: DENY");
        header("X-XSS-Protection: 1; mode=block");
        
        // Redirect
        header("Location: $url", true, $statusCode);
        exit();
    }
    
    /**
     * Block suspicious requests
     */
    public function blockSuspiciousRequests() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $suspiciousPatterns = [
            'libwww-perl', 'wget', 'python', 'nikto', 'acunetix', 'havij',
            'sqlmap', 'nmap', 'curl', 'scan', 'crawler', 'bot'
        ];
        
        foreach ($suspiciousPatterns as $pattern) {
            if (stripos($userAgent, $pattern) !== false) {
                $this->logSecurityEvent('Suspicious User Agent Blocked', $userAgent, 'WARNING');
                http_response_code(403);
                die('Access Denied');
            }
        }
        
        // Check for suspicious query parameters
        $suspiciousParams = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'script', 'javascript'];
        foreach ($_GET as $key => $value) {
            foreach ($suspiciousParams as $pattern) {
                if (stripos($value, $pattern) !== false) {
                    $this->logSecurityEvent('Suspicious Query Parameter Blocked', "$key=$value", 'WARNING');
                    http_response_code(403);
                    die('Access Denied');
                }
            }
        }
    }
    
    /**
     * Initialize router protection
     */
    public function init() {
        // Block suspicious requests
        $this->blockSuspiciousRequests();
        
        // Check if request is allowed
        if (!$this->isAllowedRequest()) {
            $this->logSecurityEvent('Unauthorized Access Attempt', $_SERVER['SCRIPT_NAME'], 'WARNING');
            $this->secureRedirect('index3.php', 403);
        }
        
        // Check if user can access current route
        if (!$this->canAccessRoute()) {
            $this->logSecurityEvent('Insufficient Permissions', $_SERVER['SCRIPT_NAME'], 'WARNING');
            $this->secureRedirect('index3.php', 403);
        }
        
        // Set security headers
        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: DENY");
        header("X-XSS-Protection: 1; mode=block");
        header("Referrer-Policy: strict-origin-when-cross-origin");
    }
}

// Initialize router protection
$router = new RouterProtection();
$router->init();
?> 