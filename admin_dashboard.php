<?php
// Include comprehensive protection
session_start();

// Additional admin-specific checks
if ($_SESSION['role'] !== 'Admin' && $_SESSION['role'] !== 'SuperAdmin') {
    SecurityMiddleware::logSecurityEvent('Unauthorized admin dashboard access', "User: {$_SESSION['user_id']}, Role: {$_SESSION['role']}", 'WARNING');
    SecurityMiddleware::secureRedirect('index3.php');
}



// Security headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' data:; font-src 'self' https://cdnjs.cloudflare.com;");

// Security check FIRST (before any output)
if (!isset($_SESSION['is_logged_in']) || $_SESSION['role'] !== 'Admin') {
    header("Location: index3.php");
    exit();
}

// CSRF Protection
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403);
        die("CSRF token validation failed");
    }
}

// Rate limiting for form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $current_time = time();
    $ip_address = $_SERVER['REMOTE_ADDR'];
    
    if (!isset($_SESSION['last_request_time'])) {
        $_SESSION['last_request_time'] = $current_time;
        $_SESSION['request_count'] = 1;
    } else {
        if ($current_time - $_SESSION['last_request_time'] < 60) { // 1 minute window
            $_SESSION['request_count']++;
            if ($_SESSION['request_count'] > 10) { // Max 10 requests per minute
                http_response_code(429);
                die("Too many requests. Please wait before trying again.");
            }
        } else {
            $_SESSION['last_request_time'] = $current_time;
            $_SESSION['request_count'] = 1;
        }
    }
}

// Session timeout (30 minutes)
if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > 1800)) {
    session_unset();
    session_destroy();
    header("Location: index3.php");
    exit();
}
$_SESSION['LAST_ACTIVITY'] = time();

// Regenerate session ID periodically for security
if (!isset($_SESSION['created'])) {
    $_SESSION['created'] = time();
} else if (time() - $_SESSION['created'] > 1800) {
    session_regenerate_id(true);
    $_SESSION['created'] = time();
}

// Prevent caching
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Database connection with enhanced security
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
    die("Database connection failed. Please try again later.");
}

// Admin ID from session with validation
$admin_id = filter_var($_SESSION['user_id'], FILTER_VALIDATE_INT);
if (!$admin_id) {
    session_destroy();
    header("Location: index3.php");
    exit();
}

// Verify admin still exists and has admin role
try {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ? AND role = 'Admin'");
    $stmt->execute([$admin_id]);
    $admin = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$admin) {
        session_destroy();
        header("Location: index3.php");
        exit();
    }
} catch (PDOException $e) {
    error_log("Admin verification error: " . $e->getMessage());
    die("An error occurred. Please try again later.");
}

// Get all QR codes with assignment status
$qrCodes = [];
try {
    $stmt = $pdo->prepare("
        SELECT q.*, u.full_name as assigned_user_name, u.email as assigned_user_email 
        FROM qr_codes q 
        LEFT JOIN users u ON q.assigned_to = u.id 
        ORDER BY q.created_at DESC
    ");
    $stmt->execute();
    $qrCodes = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("QR codes fetch error: " . $e->getMessage());
    $qrCodes = [];
}

// Get all users except current admin
$users = [];
try {
    $stmt = $pdo->prepare("SELECT id, full_name, email, mobile, age, gender, role, is_verified FROM users WHERE id != ? ORDER BY role, full_name");
    $stmt->execute([$admin_id]);
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Users fetch error: " . $e->getMessage());
    $users = [];
}

// Get admin users for display only
$admins = [];
$regularUsers = [];
foreach ($users as $user) {
    if ($user['role'] === 'Admin') {
        $admins[] = $user;
    } else {
        $regularUsers[] = $user;
    }
}

// Get available QR codes for assignment
$availableQRs = [];
try {
    $stmt = $pdo->prepare("SELECT id, code FROM qr_codes WHERE assigned_to IS NULL ORDER BY code");
    $stmt->execute();
    $availableQRs = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Available QR codes fetch error: " . $e->getMessage());
    $availableQRs = [];
}

// Get statistics
$totalUsers = count($regularUsers);
$totalAdmins = count($admins);
$totalQRCodes = count($qrCodes);
$activeQRCodes = count(array_filter($qrCodes, function($qr) { return $qr['assigned_to'] !== null; }));
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"/>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"/>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        :root {
  --primary: #38bdf8;        /* Light Blue */
  --secondary: #e0f2fe;      /* Very light blue */
  --accent: #fbbf24;         /* Soft yellow accent */
  --teal: #0ea5e9;           /* Deeper blue for contrast */
  --dark: #1e293b;           /* Dark blue-gray for text */
  --white: #ffffff;
  --light-gray: #f8fafc;
  --shadow: 0 4px 12px rgba(56, 189, 248, 0.10);
}
        body {
            background: var(--light-gray);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .dashboard-container {
            max-width: 1300px;
            margin: 20px auto;
            background: var(--white);
            border-radius: 16px;
            box-shadow: 0 6px 24px rgba(61,141,122,0.10);
            overflow: hidden;
        }
        .top-navbar {
            background: linear-gradient(135deg, var(--primary), var(--teal));
            padding: 15px 30px;
            color: var(--white);
        }
        .navbar-brand {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--white) !important;
            text-decoration: none;
        }
        .nav-tabs {
            background: var(--secondary);
            border-bottom: 2px solid var(--primary);
            padding: 0 30px;
        }
        .nav-tabs .nav-link {
            color: var(--teal);
            font-weight: 600;
            border: none;
            padding: 15px 25px;
            margin-right: 5px;
            border-radius: 0;
        }
        .nav-tabs .nav-link.active {
            background: var(--primary);
            color: var(--white);
            border-bottom: 3px solid var(--teal);
        }
        .nav-tabs .nav-link:hover {
            background: rgba(56, 189, 248, 0.1);
            color: var(--primary);
        }
        .main-content {
            padding: 30px;
        }
        .stats-row {
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, var(--white), var(--secondary));
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            border: 1px solid var(--secondary);
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            transition: transform 0.2s;
        }
        .stat-card:hover {
            transform: translateY(-2px);
        }
        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary);
            margin-bottom: 5px;
        }
        .stat-label {
            color: var(--dark);
            font-weight: 600;
        }
        .content-section {
            display: none;
            animation: fadeIn 0.3s ease-in;
        }
        .content-section.active {
            display: block;
        }
        .qr-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .qr-card {
            background: var(--white);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid var(--secondary);
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            transition: all 0.2s;
        }
        .qr-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.1);
        }
        .qr-image {
            width: 120px;
            height: 120px;
            margin: 0 auto 15px auto;
            border: 2px solid var(--secondary);
            border-radius: 8px;
            background: var(--white);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .qr-image img {
            max-width: 100%;
            max-height: 100%;
        }
        .status-active {
            background: #d4edda;
            color: var(--teal);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            display: inline-block;
        }
        .status-inactive {
            background: #f8d7da;
            color: #721c24;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            display: inline-block;
        }
        .user-table, .admin-table, .request-table {
            width: 100%;
            margin-top: 20px;
        }
        .user-table th, .admin-table th, .request-table th {
            background: var(--primary);
            color: var(--white);
            padding: 12px;
            font-weight: 600;
        }
        .user-table td, .admin-table td, .request-table td {
            padding: 12px;
            border-bottom: 1px solid var(--secondary);
            vertical-align: middle;
        }
        .user-table tbody tr:hover, .admin-table tbody tr:hover, .request-table tbody tr:hover {
            background: rgba(224, 242, 254, 0.3); /* var(--secondary) with opacity */
        }
        .btn-edit {
            background: var(--primary);
            color: var(--white);
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            margin-right: 5px;
            font-size: 0.85rem;
        }
        .btn-delete {
            background: #dc3545;
            color: var(--white);
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.85rem;
        }
        .btn-assign {
            background: #28a745;
            color: var(--white);
            border: none;
            padding: 8px 15px;
            border-radius: 6px;
            font-weight: 600;
        }
        .btn-whatsapp {
            background: #25D366;
            color: var(--white);
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.85rem;
            transition: all 0.2s;
        }
        .btn-whatsapp:hover {
            background: #128C7E;
            color: var(--white);
            transform: translateY(-1px);
        }
        .btn-email {
            background: #007bff;
            color: var(--white);
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.85rem;
            transition: all 0.2s;
        }
        .btn-email:hover {
            background: #0056b3;
            color: var(--white);
            transform: translateY(-1px);
        }
        .action-buttons {
            display: flex;
            gap: 4px;
            flex-wrap: wrap;
            align-items: center;
        }
        .action-buttons .btn {
            margin: 0;
            white-space: nowrap;
        }
        .request-card {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #3D8D7A;
        }
        .logout-btn {
            background: #dc3545;
            color: var(--white);
            border: none;
            padding: 8px 20px;
            border-radius: 6px;
            font-weight: 600;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @media (max-width: 768px) {
            .qr-grid {
                grid-template-columns: 1fr;
            }
            .main-content {
                padding: 20px 15px;
            }
        }
    </style>
</head>
<body>
<div class="dashboard-container">
    <!-- Top Navbar -->
    <div class="top-navbar d-flex justify-content-between align-items-center">
        <a href="#" class="navbar-brand">
            <i class="fas fa-user-shield me-2"></i>Admin Dashboard
        </a>
        <div class="d-flex align-items-center">
            <span class="me-3">Welcome, <strong><?= htmlspecialchars($_SESSION['full_name']) ?></strong></span>
            <form action="logout.php" method="post" class="d-inline">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <button type="submit" class="logout-btn">
                    <i class="fas fa-sign-out-alt me-1"></i>Logout
                </button>
            </form>
        </div>
    </div>
    <!-- Navigation Tabs -->
    <ul class="nav nav-tabs" id="adminTabs" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link active" id="dashboard-tab" data-bs-toggle="tab" data-bs-target="#dashboard" type="button" role="tab">
                <i class="fas fa-chart-bar me-2"></i>Dashboard
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="qrcodes-tab" data-bs-toggle="tab" data-bs-target="#qrcodes" type="button" role="tab">
                <i class="fas fa-qrcode me-2"></i>QR Codes
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="users-tab" data-bs-toggle="tab" data-bs-target="#users" type="button" role="tab">
                <i class="fas fa-users me-2"></i>Users
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="admins-tab" data-bs-toggle="tab" data-bs-target="#admins" type="button" role="tab">
                <i class="fas fa-user-shield me-2"></i>Admins
            </button>
        </li>
    </ul>

    <div class="main-content">
        <div class="tab-content" id="adminTabsContent">
            
            <!-- Dashboard Tab -->
            <div class="tab-pane fade show active" id="dashboard" role="tabpanel">
                <h3 class="mb-4" style="color: var(--primary);">
                    <i class="fas fa-chart-bar me-2"></i>Dashboard Overview
                </h3>
                <div class="row stats-row">
                    <div class="col-md-3 col-6 mb-3">
                        <div class="stat-card">
                            <div class="stat-number"><?= $totalUsers ?></div>
                            <div class="stat-label">Total Users</div>
                        </div>
                    </div>
                    <div class="col-md-3 col-6 mb-3">
                        <div class="stat-card">
                            <div class="stat-number"><?= $totalAdmins ?></div>
                            <div class="stat-label">Total Admins</div>
                        </div>
                    </div>
                    <div class="col-md-3 col-6 mb-3">
                        <div class="stat-card">
                            <div class="stat-number"><?= $totalQRCodes ?></div>
                            <div class="stat-label">Total QR Codes</div>
                        </div>
                    </div>
                    <div class="col-md-3 col-6 mb-3">
                        <div class="stat-card">
                            <div class="stat-number"><?= $activeQRCodes ?></div>
                            <div class="stat-label">Active QRs</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- QR Codes Tab -->
            <div class="tab-pane fade" id="qrcodes" role="tabpanel">
                <h3 class="mb-4" style="color: var(--primary);">
                    <i class="fas fa-qrcode me-2"></i>QR Code Management
                </h3>
                <div class="qr-grid">
                    <?php foreach ($qrCodes as $qr): ?>
                        <div class="qr-card">
                            <div class="text-center mb-3">
                                <strong>QR Code: <?= htmlspecialchars($qr['code']) ?></strong>
                            </div>
                            <div class="qr-image">
    <img id="qr-img-<?= $qr['id'] ?>" src="data:image/png;base64,<?= $qr['image_data'] ?>" alt="QR Code">
</div>
<div class="d-flex justify-content-center gap-2 mt-2">
    <button class="btn btn-outline-primary btn-sm" onclick="printQRCode('qr-img-<?= $qr['id'] ?>')">
        <i class="fas fa-print"></i> Print
    </button>
    <button class="btn btn-outline-success btn-sm" onclick="downloadQRCode('qr-img-<?= $qr['id'] ?>', '<?= htmlspecialchars($qr['code']) ?>')">
        <i class="fas fa-download"></i> Download
    </button>
</div>
                            <div class="text-center mt-3">
                                <?php if ($qr['assigned_to']): ?>
                                    <div class="status-active mb-2">
                                        <i class="fas fa-check-circle me-1"></i>Active
                                    </div>
                                    <div class="text-muted">
                                        <strong>Assigned to:</strong><br>
                                        <?= htmlspecialchars($qr['assigned_user_name']) ?><br>
                                        <small><?= htmlspecialchars($qr['assigned_user_email']) ?></small>
                                    </div>
                                <?php else: ?>
                                    <div class="status-inactive">
                                        <i class="fas fa-times-circle me-1"></i>Inactive
                                    </div>
                                    <div class="text-muted mt-2">Not assigned to any user</div>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
                <?php if (empty($qrCodes)): ?>
                    <div class="text-center py-5">
                        <i class="fas fa-qrcode fa-3x text-muted mb-3"></i>
                        <h5 class="text-muted">No QR Codes Available</h5>
                        <p class="text-muted">QR codes will appear here once created by Super Admin.</p>
                    </div>
                <?php endif; ?>
            </div>
            <!-- Users Tab -->
            <div class="tab-pane fade" id="users" role="tabpanel">
                <h3 class="mb-4" style="color: var(--primary);">
                    <i class="fas fa-users me-2"></i>User Management
                </h3>
                <?php if (!empty($regularUsers)): ?>
                    <div class="table-responsive">
                        <table class="table user-table">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Email</th>
                                    <th>Mobile</th>
                                    <th>Age</th>
                                    <th>Gender</th>
                                    <th>Verified</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($regularUsers as $user): ?>
    <tr>
        <td><?= htmlspecialchars($user['full_name']) ?></td>
        <td><?= htmlspecialchars($user['email']) ?></td>
        <td><?= htmlspecialchars($user['mobile']) ?></td>
        <td><?= htmlspecialchars($user['age']) ?></td>
        <td><?= htmlspecialchars($user['gender']) ?></td>
        <td>
            <span class="badge bg-<?= $user['is_verified'] ? 'success' : 'warning' ?>">
                <?= $user['is_verified'] ? 'Yes' : 'No' ?>
            </span>
        </td>
        <td>
            <div class="action-buttons">
            <button class="btn-edit" onclick="window.location.href='edit_user.php?id=<?= $user['id'] ?>'">
    <i class="fas fa-edit"></i> Edit
</button>

                <button class="btn-delete" onclick="deleteUser(<?= $user['id'] ?>, '<?= htmlspecialchars($user['full_name']) ?>')">
                    <i class="fas fa-trash"></i> Delete
                </button>
                <button class="btn-whatsapp" onclick="sendViaWhatsApp('<?= htmlspecialchars($user['mobile']) ?>', '<?= htmlspecialchars($user['full_name']) ?>')">
                    <i class="fab fa-whatsapp"></i> WhatsApp
                </button>
                <button class="btn-email" onclick="sendViaMail('<?= htmlspecialchars($user['email']) ?>', '<?= htmlspecialchars($user['full_name']) ?>', '<?= htmlspecialchars($user['mobile']) ?>', '<?= htmlspecialchars($user['age']) ?>', '<?= htmlspecialchars($user['gender']) ?>')">
                    <i class="fas fa-envelope"></i> Email
                </button>
            </div>
        </td>
    </tr>
<?php endforeach; ?>

                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <div class="text-center py-5">
                        <i class="fas fa-users fa-3x text-muted mb-3"></i>
                        <h5 class="text-muted">No Users Found</h5>
                    </div>
                <?php endif; ?>
            </div>
            <!-- Admins Tab -->
            <div class="tab-pane fade" id="admins" role="tabpanel">
                <h3 class="mb-4" style="color: var(--primary);">
                    <i class="fas fa-user-shield me-2"></i>Admin Users (View Only)
                </h3>
                <?php if (!empty($admins)): ?>
                    <div class="table-responsive">
                        <table class="table admin-table">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Email</th>
                                    <th>Mobile</th>
                                    <th>Age</th>
                                    <th>Gender</th>
                                    <th>Verified</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($admins as $admin): ?>
                                    <tr>
                                        <td><?= htmlspecialchars($admin['full_name']) ?></td>
                                        <td><?= htmlspecialchars($admin['email']) ?></td>
                                        <td><?= htmlspecialchars($admin['mobile']) ?></td>
                                        <td><?= htmlspecialchars($admin['age']) ?></td>
                                        <td><?= htmlspecialchars($admin['gender']) ?></td>
                                        <td>
                                            <span class="badge bg-<?= $admin['is_verified'] ? 'success' : 'warning' ?>">
                                                <?= $admin['is_verified'] ? 'Yes' : 'No' ?>
                                            </span>
                                        </td>
                                        <td>
                                            <span class="badge bg-primary">View Only</span>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <div class="text-center py-5">
                        <i class="fas fa-user-shield fa-3x text-muted mb-3"></i>
                        <h5 class="text-muted">No Other Admins Found</h5>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<!-- Features Section -->
<section style="padding: 50px 20px; background: var(--secondary); border-top: 3px solid var(--primary);">
    <div class="container text-center">
        <h2 style="color: var(--primary); font-weight: 700;" class="mb-4">
            <i class="fas fa-star me-2"></i>Why Choose Addwise?
        </h2>
        <div class="row justify-content-center g-4">
            <!-- Card 1 -->
            <div class="col-md-4">
                <div class="p-4 rounded shadow-sm bg-white h-100">
                    <i class="fas fa-lock fa-2x mb-3 text-success"></i>
                    <h5 class="fw-bold mb-2">Secure Admin Controls</h5>
                    <p class="text-muted">Role-based access ensures only verified admins can manage users and QR data.</p>
                </div>
            </div>
            <!-- Card 2 -->
            <div class="col-md-4">
                <div class="p-4 rounded shadow-sm bg-white h-100">
                    <i class="fas fa-qrcode fa-2x mb-3 text-info"></i>
                    <h5 class="fw-bold mb-2">Smart QR Management</h5>
                    <p class="text-muted">Generate, assign, and track QR codes efficiently for any user or request.</p>
                </div>
            </div>
            <!-- Card 3 -->
            <div class="col-md-4">
                <div class="p-4 rounded shadow-sm bg-white h-100">
                    <i class="fas fa-users fa-2x mb-3 text-primary"></i>
                    <h5 class="fw-bold mb-2">User & Admin Insights</h5>
                    <p class="text-muted">View user details, verification status, and manage admin privileges seamlessly.</p>
                </div>
            </div>
            <!-- Card 4 -->
            <div class="col-md-4">
                <div class="p-4 rounded shadow-sm bg-white h-100">
                    <i class="fas fa-clock fa-2x mb-3 text-warning"></i>
                    <h5 class="fw-bold mb-2">Real-Time Requests</h5>
                    <p class="text-muted">Monitor and approve QR code requests instantly with assignment tools built in.</p>
                </div>
            </div>
            <!-- Card 5 -->
            <div class="col-md-4">
                <div class="p-4 rounded shadow-sm bg-white h-100">
                    <i class="fas fa-chart-pie fa-2x mb-3 text-danger"></i>
                    <h5 class="fw-bold mb-2">Data Overview</h5>
                    <p class="text-muted">Visual dashboard stats show QR activity, user counts, and pending actions at a glance.</p>
                </div>
            </div>
        </div>
    </div>
</section>
<footer style="background-color: var(--primary); color: var(--white); padding: 20px 30px; margin-top: 50px; border-top: 4px solid var(--teal);">
    <div class="d-flex flex-column flex-md-row justify-content-between align-items-center">
        <p class="mb-2 mb-md-0">&copy; <?= date("Y") ?> Addwise Admin Panel. All rights reserved.</p>
    </div>
</footer>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
// Security: Prevent XSS in user input
function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

// Security: Validate user ID
function validateUserId(userId) {
    return /^\d+$/.test(userId) && userId > 0;
}

// Security: Validate user name
function validateUserName(userName) {
    return typeof userName === 'string' && userName.length > 0 && userName.length < 100;
}

function editUser(userId) {
    // Security: Validate input
    if (!validateUserId(userId)) {
        console.error('Invalid user ID');
        return;
    }
    
    // Redirect to edit user page with CSRF protection
    const form = document.createElement('form');
    form.method = 'post';
    form.action = 'edit_user.php';
    
    const userIdInput = document.createElement('input');
    userIdInput.type = 'hidden';
    userIdInput.name = 'user_id';
    userIdInput.value = userId;
    
    const csrfInput = document.createElement('input');
    csrfInput.type = 'hidden';
    csrfInput.name = 'csrf_token';
    csrfInput.value = '<?= $_SESSION['csrf_token'] ?>';
    
    form.appendChild(userIdInput);
    form.appendChild(csrfInput);
    document.body.appendChild(form);
    form.submit();
}

function deleteUser(userId, userName) {
    // Security: Validate inputs
    if (!validateUserId(userId) || !validateUserName(userName)) {
        console.error('Invalid input parameters');
        return;
    }
    
    // Security: Sanitize user name for display
    const sanitizedUserName = sanitizeInput(userName);
    
    if (confirm('Are you sure you want to delete user: ' + sanitizedUserName + '?')) {
        // Create form with CSRF protection
        var form = document.createElement('form');
        form.method = 'post';
        form.action = 'delete_user.php';
        
        // User ID
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'user_id';
        input.value = userId;
        form.appendChild(input);
        
        // CSRF Token
        var csrf = document.createElement('input');
        csrf.type = 'hidden';
        csrf.name = 'csrf_token';
        csrf.value = '<?= $_SESSION['csrf_token'] ?>';
        form.appendChild(csrf);
        
        document.body.appendChild(form);
        form.submit();
    }
}

// Security: Prevent back button navigation
history.pushState(null, null, location.href);
window.onpopstate = function() { 
    history.go(1); 
};

window.addEventListener('pageshow', function(event) {
    if (event.persisted || (window.performance && window.performance.navigation.type === 2)) {
        window.location.reload();
    }
});

// Security: Validate image ID
function validateImageId(imgId) {
    return typeof imgId === 'string' && /^qr-img-\d+$/.test(imgId);
}

// Security: Validate QR code
function validateQRCode(code) {
    return typeof code === 'string' && /^[A-Za-z0-9]+$/.test(code) && code.length <= 50;
}

function printQRCode(imgId) {
    // Security: Validate input
    if (!validateImageId(imgId)) {
        console.error('Invalid image ID');
        return;
    }
    
    var img = document.getElementById(imgId);
    if (!img) {
        console.error('Image not found');
        return;
    }
    
    var win = window.open('', '_blank');
    win.document.write('<html><head><title>Print QR Code</title></head><body style="text-align:center;">');
    win.document.write('<img src="' + img.src + '" style="width:200px;height:200px;"/>');
    win.document.write('</body></html>');
    win.document.close();
    win.focus();
    win.print();
    setTimeout(function() { win.close(); }, 1000);
}

function downloadQRCode(imgId, code) {
    // Security: Validate inputs
    if (!validateImageId(imgId) || !validateQRCode(code)) {
        console.error('Invalid input parameters');
        return;
    }
    
    var img = document.getElementById(imgId);
    if (!img) {
        console.error('Image not found');
        return;
    }
    
    var link = document.createElement('a');
    link.href = img.src;
    link.download = code + '_qrcode.png';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Security: Validate phone number
function validatePhone(phone) {
    return typeof phone === 'string' && /^[\d\s\+\-\(\)]+$/.test(phone) && phone.length >= 10;
}

// Security: Validate email
function validateEmail(email) {
    return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sendViaWhatsApp(phone, userName) {
    // Security: Validate inputs
    if (!validatePhone(phone) || !validateUserName(userName)) {
        console.error('Invalid phone number or user name');
        return;
    }
    
    // Security: Sanitize inputs
    const sanitizedPhone = phone.replace(/[^\d]/g, '');
    const sanitizedName = sanitizeInput(userName);
    
    // Add +91 prefix for Indian numbers if not already present
    let formattedPhone = sanitizedPhone;
    if (formattedPhone.length === 10) {
        formattedPhone = '91' + formattedPhone;
    } else if (formattedPhone.startsWith('0')) {
        formattedPhone = '91' + formattedPhone.substring(1);
    }
    
    // Create WhatsApp message
    let message = encodeURIComponent(`Hello ${sanitizedName}! This is a message from Addwise Admin Panel. Please contact us if you need any assistance with your QR code or account.`);
    
    // Open WhatsApp with the message
    window.open(`https://wa.me/${formattedPhone}?text=${message}`, '_blank');
}

function sendViaMail(email, userName, mobile, age, gender) {
    // Security: Validate inputs
    if (!validateEmail(email) || !validateUserName(userName)) {
        console.error('Invalid email or user name');
        return;
    }
    
    // Security: Sanitize inputs
    const sanitizedEmail = email.trim();
    const sanitizedName = sanitizeInput(userName);
    const sanitizedMobile = mobile ? sanitizeInput(mobile) : 'N/A';
    const sanitizedAge = age ? sanitizeInput(age) : 'N/A';
    const sanitizedGender = gender ? sanitizeInput(gender) : 'N/A';
    
    // Format all user details in a single line
    const userDetails = `Name: ${sanitizedName}, Mobile: ${sanitizedMobile}, Age: ${sanitizedAge}, Gender: ${sanitizedGender}`;
    
    // Prepare email content
    let subject = encodeURIComponent("Addwise - User Information");
    let body = encodeURIComponent(`Hello ${sanitizedName},\n\nThis is a message from Addwise Admin Panel.\n\nUser Details: ${userDetails}\n\nPlease contact us if you need any assistance with your QR code or account.\n\nBest regards,\nAddwise Admin Team`);
    
    // Open email client
    window.location.href = `mailto:${sanitizedEmail}?subject=${subject}&body=${body}`;
}

// Security: Add event listeners with error handling
document.addEventListener('DOMContentLoaded', function() {
    // Prevent form resubmission
    if (window.history.replaceState) {
        window.history.replaceState(null, null, window.location.href);
    }
    
    // Add security headers to all AJAX requests
    const originalFetch = window.fetch;
    window.fetch = function(url, options = {}) {
        options.headers = {
            ...options.headers,
            'X-Requested-With': 'XMLHttpRequest'
        };
        return originalFetch(url, options);
    };
});
</script>
</body>
</html>
