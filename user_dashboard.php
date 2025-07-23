<?php
session_start();
require_once 'protection.php';

// Security headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: "
    . "default-src 'self'; "
    . "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com https://maps.googleapis.com; "
    . "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
    . "img-src 'self' data: https://maps.googleapis.com https://maps.gstatic.com; "
    . "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
    . "connect-src 'self' https://maps.googleapis.com https://maps.gstatic.com; "
    . "frame-src 'self';"
);

header("Permissions-Policy: geolocation=(self), camera=(self)");

// Security check FIRST (before any output)
if (!isset($_SESSION['is_logged_in']) || $_SESSION['role'] !== 'User') {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Unauthorized access']);
    exit;
}

// CSRF Protection
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die(json_encode(['success' => false, 'message' => 'Invalid CSRF token']));
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
                echo json_encode(['success' => false, 'message' => 'Too many requests. Please wait before trying again.']);
                exit;
            }
        } else {
            $_SESSION['last_request_time'] = $current_time;
            $_SESSION['request_count'] = 1;
        }
    }
}

// Database connection with enhanced security
$host = 'localhost';
$dbname = 'addwise';
$username = 'root';
$password = '123456';   
// Before your PDO connection
error_reporting(E_ALL);
ini_set('display_errors', 1);

// In your db_connection.php
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false
    ]);
} catch (PDOException $e) {
    error_log("Database connection failed: " . $e->getMessage());
    throw new Exception("Database connection failed");
}

// User ID from session with validation
$user_id = filter_var($_SESSION['user_id'], FILTER_VALIDATE_INT);
if (!$user_id) {
    session_destroy();
    header("Location: index3.php");
    exit();
}

// 🚨 QR DELETION HANDLER MUST COME HERE 🚨
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_qr_id'])) {
    $delete_id = filter_var($_POST['delete_qr_id'], FILTER_VALIDATE_INT);
    if ($delete_id) {
        try {
            $stmt = $pdo->prepare("DELETE FROM qr_codes WHERE id = ? AND assigned_to = ?");
            $stmt->execute([$delete_id, $user_id]);
            
            if ($stmt->rowCount() > 0) {
                $_SESSION['message'] = "QR code deleted successfully.";
            } else {
                $_SESSION['error'] = "QR code not found or you don't have permission to delete it.";
            }
        } catch (PDOException $e) {
            error_log("QR deletion error: " . $e->getMessage());
            $_SESSION['error'] = "An error occurred while deleting the QR code.";
        }
    } else {
        $_SESSION['error'] = "Invalid QR code ID.";
    }
    header("Location: ".$_SERVER['PHP_SELF']);
    exit();
}

// Fetch user details with validation
try {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ? AND role = 'User'");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        session_destroy();
        header("Location: index3.php");
        exit();
    }
} catch (PDOException $e) {
    error_log("User fetch error: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'An error occurred. Please try again later.']);
    exit;
}

// Fetch assigned QR codes with assignment date
try {
    $stmt = $pdo->prepare("
        SELECT q.*, r.requested_at AS assignment_date 
        FROM qr_codes q
        LEFT JOIN qr_requests r ON q.id = r.assigned_qr_id
        WHERE q.assigned_to = ?
        ORDER BY q.created_at DESC
    ");
    $stmt->execute([$user_id]);
    $qr_codes = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("QR codes fetch error: " . $e->getMessage());
    $qr_codes = [];
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #3D8D7A;
            --light: #B3D8A8;
            --bg: #FBFFE4;
            --accent: #A3D1C6;
            --white: #fff;
        }
        body {
            background: var(--bg);
            font-family: 'Segoe UI', 'Arial', sans-serif;
            min-height: 100vh;
            padding-top: 32px;
        }
        .dashboard-header {
            background: linear-gradient(90deg, var(--primary) 70%, var(--accent) 100%);
            color: var(--white);
            border-radius: 20px;
            padding: 32px 36px 24px 36px;
            margin-bottom: 36px;
            box-shadow: 0 8px 32px 0 rgba(61, 141, 122, 0.12);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .dashboard-header h1 {
            font-weight: 700;
            font-size: 2.1rem;
            letter-spacing: 1px;
            margin: 0;
        }
        .profile-actions .btn {
            margin-left: 10px;
            font-weight: 500;
            border-radius: 10px;
            padding: 8px 18px;
            font-size: 1rem;
            transition: background 0.2s, color 0.2s;
        }
        .btn-profile {
            background: var(--accent);
            color: var(--primary);
            border: none;
        }
        .btn-profile:hover {
            background: var(--light);
            color: var(--primary);
        }
        .btn-edit {
            background: var(--primary);
            color: var(--white);
            border: 2px solid var(--accent);
        }
        .btn-edit:hover {
            background: var(--accent);
            color: var(--primary);
        }
        .btn-logout {
            background: var(--white);
            color: var(--primary);
            border: 2px solid var(--primary);
        }
        .btn-logout:hover {
            background: var(--primary);
            color: var(--white);
        }
        .card {
            background: var(--white);
            border-radius: 18px;
            box-shadow: 0 6px 24px 0 rgba(61, 141, 122, 0.13);
            border: none;
            margin-bottom: 28px;
        }
        .card-header {
            background: var(--primary) !important;
            color: var(--white) !important;
            border-radius: 18px 18px 0 0 !important;
            font-weight: 600;
            font-size: 1.25rem;
            padding: 18px 24px;
            letter-spacing: 0.5px;
        }
        .card-body {
            background: var(--bg);
            border-radius: 0 0 18px 18px;
            padding: 36px 28px;
        }
        .qr-image {
            border: 2.5px solid var(--light);
            border-radius: 14px;
            padding: 14px;
            background: var(--white);
            max-width: 230px;
            box-shadow: 0 2px 12px 0 rgba(163, 209, 198, 0.18);
        }
        .alert-info, .alert-warning {
            background: var(--accent);
            color: var(--primary);
            border: none;
            border-radius: 10px;
            font-size: 1.07rem;
        }
        .alert-info i, .alert-warning i {
            color: var(--primary);
        }
        .location-display {
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            color: var(--primary);
            background: var(--light);
            padding: 2px 6px;
            border-radius: 4px;
            display: inline-block;
        }
        .tracking-item.active {
            background: var(--accent);
            border-color: var(--primary);
        }
        .tracking-item.active .text-muted {
            color: var(--primary) !important;
        }
        @media (max-width: 767px) {
            .dashboard-header {
                flex-direction: column;
                align-items: flex-start;
                padding: 18px 10px;
            }
            .dashboard-header h1 {
                font-size: 1.3rem;
            }
     .profile-actions {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: nowrap; /* Prevent wrapping */
    flex-shrink: 0;
}

            .card-body {
                padding: 22px 10px;
            }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="dashboard-header">
        <h1>
            <i class="fas fa-user-circle me-2"></i> 
            Hello!, <?php echo htmlspecialchars($user['full_name']); ?>
        </h1>
        <div class="profile-actions">
            <a href="view_profile_users.php" class="btn btn-profile">
                <i class="fas fa-id-badge me-1"></i> View Profile
            </a>
            <a href="edit_profile_users.php" class="btn btn-edit">
                <i class="fas fa-user-edit me-1"></i> Edit Profile
            </a>
            <a href="logout.php" class="btn btn-logout">
                <i class="fas fa-sign-out-alt me-1"></i> Logout
            </a>
        </div>
    </div>
<?php if (isset($_SESSION['message'])): ?>
    <div class="alert alert-success"><?= htmlspecialchars($_SESSION['message']) ?></div>
    <?php unset($_SESSION['message']); ?>
<?php elseif (isset($_SESSION['error'])): ?>
  <div class="alert alert-danger"><?= htmlspecialchars($_SESSION['error']) ?></div>
    <?php unset($_SESSION['error']); ?>
<?php endif; ?>

<!-- Action Buttons Row -->
<div class="card p-3 mb-3">
    <div class="row align-items-center">
        <div class="col-md-4">
            <a href="#" class="btn btn-primary w-100" data-bs-toggle="modal" data-bs-target="#addDeviceModal">
                <i class="fas fa-camera me-1"></i> Add Device
            </a>
        </div>
        <div class="col-md-4">
            <a href="#" class="btn btn-success w-100" data-bs-toggle="modal" data-bs-target="#uploadFileModal">
                <i class="fas fa-upload me-1"></i> Upload File
            </a>
        </div>
        <div class="col-md-4">
            <button type="button" class="btn btn-info w-100" data-bs-toggle="collapse" data-bs-target="#manualInputCollapse">
                <i class="fas fa-keyboard me-1"></i> Add Code Manually
            </button>
        </div>
    </div>
    
    <!-- Collapsible Manual Input Form -->
    <div class="collapse mt-3" id="manualInputCollapse">
        <div class="card card-body bg-light">
            <h6>Enter QR Code Manually</h6>
            <form id="manualQrForm">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <div class="input-group">
                    <input type="text" id="manual_qr" name="manual_qr" class="form-control" placeholder="Enter 16-digit QR code" maxlength="16" required pattern="\d{16}">
                    <button type="submit" class="btn btn-primary">Add Device</button>
                </div>
            </form>
        </div>
    </div>
</div>

   <!-- QR Code Section -->
<div class="card">
    <div class="card-header">
        <i class="fas fa-qrcode me-2"></i> Your QR Code
    </div>
    <div class="card-body">
        <?php if (!empty($qr_codes)): ?>
            <?php foreach ($qr_codes as $qr): ?>
                <div class="qr-box mb-4 p-3 border rounded">
                    <div class="row align-items-center">
                        <div class="col-md-4 text-center">
                            <?php if (!empty($qr['image_data'])): ?>
                                <img src="data:image/png;base64,<?= $qr['image_data'] ?>" 
                                     class="img-fluid qr-image" alt="QR Code">
                            <?php else: ?>
                                <div class="alert alert-warning p-2">
                                    <i class="fas fa-exclamation-triangle me-2"></i>
                                    QR image missing
                                </div>
                        <?php endif; ?>
                        </div>
                        <div class="col-md-8">
                            <h5>QR Code Details</h5>
                            <ul class="list-unstyled">
                                <li><strong>Code:</strong> <?= htmlspecialchars($qr['code']) ?></li>
                                <?php if ($qr['created_at']): ?>
                                    <li><strong>Assigned:</strong> <?= date('M d, Y h:i A', strtotime($qr['created_at'])) ?></li>
                                <?php else: ?>
                                    <li><strong>Assigned:</strong> Not available</li>
                                <?php endif; ?>
                                <li><strong>Location:</strong> <span id="qr-location-<?= $qr['id'] ?>" class="location-display">Not available</span></li>
                            </ul>
                            <!-- Button Row -->
                            <div class="d-flex gap-2 mt-3">
                                <!-- GPS Tracking Buttons -->
                                <button class="btn btn-info btn-sm" onclick="trackLocation(<?= $qr['id'] ?>, '<?= htmlspecialchars($qr['code']) ?>')">
                                    <i class="fas fa-map-marker-alt me-1"></i> Track Location
                                </button>
                                <button class="btn btn-warning btn-sm" onclick="stopLocationSharing(<?= $qr['id'] ?>)">
                                    <i class="fas fa-stop-circle me-1"></i> Stop Sharing
                                </button>
                                <button class="btn btn-secondary btn-sm" onclick="addLocationManually(<?= $qr['id'] ?>, '<?= htmlspecialchars($qr['code']) ?>')">
                                    <i class="fas fa-plus me-1"></i> Add Location
                                </button>
                                <!-- Delete Button -->
                                <form method="post" action="" onsubmit="return confirm('Are you sure you want to delete this QR code?');" class="d-inline">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                    <input type="hidden" name="delete_qr_id" value="<?= htmlspecialchars($qr['id']) ?>">
                                    <button type="submit" class="btn btn-danger btn-sm">
                                        <i class="fas fa-trash-alt me-1"></i> Delete
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="alert alert-info">
                <i class="fas fa-info-circle me-2"></i>
                No QR codes assigned yet. Scan a QR code to get started.
            </div>
      
        <?php endif; ?>
    </div>
</div>


<!-- GPS Tracking Section -->
<div class="card">
    <div class="card-header">
        <i class="fas fa-map-marker-alt me-2"></i> GPS Tracking
    </div>
    <div class="card-body">
        <div class="row position-relative">
            <!-- Arrows container (positioned absolutely between columns) -->
            <div class="arrows-container">
                <?php if (!empty($qr_codes)): ?>
                    <?php foreach ($qr_codes as $index => $qr): ?>
                        <div class="red-arrow" id="arrow-<?= $qr['id'] ?>" style="display: none;"></div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            
            <div class="col-md-8">
                <div id="map" style="height: 400px; width: 100%; border-radius: 10px;"></div>
            </div>
            <div class="col-md-4">
                <h6>Tracked QR Codes</h6>
                <div id="tracking-list">
                    <?php if (!empty($qr_codes)): ?>
                        <?php foreach ($qr_codes as $qr): ?>
                            <div class="tracking-item mb-2 p-2 border rounded" id="tracking-<?= $qr['id'] ?>" data-qr-id="<?= $qr['id'] ?>">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <strong><?= htmlspecialchars($qr['code']) ?></strong>
                                        <div class="text-muted small" id="location-<?= $qr['id'] ?>">Location not available</div>
                                    </div>
                                    <div class="tracking-status" id="status-<?= $qr['id'] ?>">
                                        <span class="badge bg-secondary">Not Tracking</span>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <p class="text-muted">No QR codes to track</p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>
<!-- Add Device Modal -->
<div class="modal fade" id="addDeviceModal" tabindex="-1" ">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="addDeviceModalLabel">
                    <i class="fas fa-qrcode me-2"></i>Scan QR Code
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body text-center">
                <div id="qr-reader" style="width: 100%; max-width: 500px; margin: 0 auto;"></div>
                <p class="mt-3 text-muted">
                    <i class="fas fa-info-circle me-1"></i>
                    Position the QR code within the scanning area
                </p>
            </div>
    
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                    <i class="fas fa-times me-1"></i>Cancel
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Upload QR File Modal -->
<div class="modal fade" id="uploadFileModal" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
      <form action="upload_qr_file.php" method="POST" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <div class="modal-header">
          <h5 class="modal-title" id="uploadFileModalLabel">Upload QR Image</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body text-center">
          <input type="file" name="qr_image" class="form-control" accept="image/*" required>
          <p class="text-muted mt-2"><i class="fas fa-info-circle me-1"></i>Select a QR image file (PNG, JPG, etc.)</p>
        </div>
        <div class="modal-footer">
          <button type="submit" class="btn btn-primary">Upload & Assign</button>
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- Manual Location Modal -->
<div class="modal fade" id="manualLocationModal" tabindex="-1" >
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="manualLocationModalLabel">
          <i class="fas fa-map-marker-alt me-2"></i>Add Location Manually
        </h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <form id="manualLocationForm">
          <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
          <input type="hidden" id="manual_qr_id" name="qr_id">
          <div class="mb-3">
            <label for="latitude" class="form-label">Latitude</label>
            <input type="number" step="any" class="form-control" id="latitude" name="latitude" required placeholder="e.g., 12.9716">
          </div>
          <div class="mb-3">
            <label for="longitude" class="form-label">Longitude</label>
            <input type="number" step="any" class="form-control" id="longitude" name="longitude" required placeholder="e.g., 77.5946">
          </div>
          <div class="mb-3">
            <label for="location_name" class="form-label">Location Name (Optional)</label>
            <input type="text" class="form-control" id="location_name" name="location_name" placeholder="e.g., Home, Office">
          </div>
          <div class="d-grid">
            <button type="submit" class="btn btn-primary">
              <i class="fas fa-save me-1"></i>Save Location
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</div>

<!-- GPS Tracking Modal -->
<div class="modal fade" id="gpsTrackingModal" tabindex="-1">
  <div class="modal-dialog modal-lg">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="gpsTrackingModalLabel">
          <i class="fas fa-satellite me-2"></i>Live GPS Tracking
        </h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <div class="row">
          <div class="col-md-8">
            <div id="tracking-map" style="height: 400px; width: 100%; border-radius: 10px;"></div>
          </div>
          <div class="col-md-4">
            <h6>Active Tracking</h6>
            <div id="active-tracking-list">
              <!-- Active tracking items will be populated here -->
            </div>
            <hr>
            <h6>Current Location</h6>
            <div id="current-location-info">
              <p class="text-muted">Getting location...</p>
            </div>
            <hr>
            <h6>Tracking Controls</h6>
            <button class="btn btn-success btn-sm" onclick="startLiveTracking()">
              <i class="fas fa-play me-1"></i>Start Tracking
            </button>
            <button class="btn btn-danger btn-sm" onclick="stopLiveTracking()">
              <i class="fas fa-stop me-1"></i>Stop Tracking
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Features Section -->
<section style="padding: 50px 20px; background: #f2fdfc; border-top: 3px solid #3D8D7A;">
    <div class="container text-center">
        <h2 style="color: #3D8D7A; font-weight: 700;" class="mb-4">
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
<footer style="background-color: #3D8D7A; color: white; padding: 20px 30px; margin-top: 50px; border-top: 4px solid #2a6d5e;">
    <div class="d-flex flex-column flex-md-row justify-content-between align-items-center">
        <p class="mb-2 mb-md-0">&copy; <?= date("Y") ?> Addwise Admin Panel. All rights reserved.</p>
    </div>
</footer>
<script src="https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js"></script>
<script
  src="https://maps.googleapis.com/maps/api/js?key=AIzaSyBojRzQi1dWQ6LdRiXX0OBleyXDQbRdLqs&libraries=places&callback=initMap"
  async
  defer
></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
let qrScanner=null;
let map;
let trackingMap;
let markers = {};
let currentTrackingQR = null;
let locationUpdateInterval = null;
let trackingStates = {}; // Store tracking states for persistence

// Initialize Google Maps
function initMap() {
    try {
        const defaultLocation = { lat: 20.5937, lng: 78.9629 };
        map = new google.maps.Map(document.getElementById('map'), {
            zoom: 5,
            center: defaultLocation,
            mapTypeId: google.maps.MapTypeId.ROADMAP
        });
        loadExistingLocations();
        loadTrackingStates(); // Load saved tracking states
    } catch (error) {
        console.error('Google Maps initialization error:', error);
        document.getElementById('map').innerHTML = 
            '<div class="alert alert-danger">Failed to load Google Maps. Please try again later.</div>';
    }
}

// Load existing locations from database
function loadExistingLocations() {
    fetch('get_qr_locations.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'csrf_token=' + encodeURIComponent('<?= $_SESSION['csrf_token'] ?>')
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            data.locations.forEach(location => {
                addMarkerToMap(location.qr_id, location.latitude, location.longitude, location.location_name || location.qr_code);
                updateLocationDisplay(location.qr_id, location.latitude, location.longitude, location.location_name);
                updateQRLocationDisplay(location.qr_id, location.latitude, location.longitude, location.location_name);
            });
            updateMainMapLiveMarkers();
        }
    })
    .catch(error => {
        console.error('Error loading locations:', error);
    });
}

// Load tracking states from localStorage
function loadTrackingStates() {
    const savedStates = localStorage.getItem('trackingStates');
    if (savedStates) {
        trackingStates = JSON.parse(savedStates);
        // Restore tracking for active QR codes
        Object.keys(trackingStates).forEach(qrId => {
            if (trackingStates[qrId].isTracking) {
                restoreTracking(qrId);
            }
        });
    }
}

// Save tracking states to localStorage
function saveTrackingStates() {
    localStorage.setItem('trackingStates', JSON.stringify(trackingStates));
}

// Restore tracking for a QR code
function restoreTracking(qrId) {
    const statusElement = document.getElementById(`status-${qrId}`);
    if (statusElement) {
        statusElement.innerHTML = '<span class="badge bg-success">Live Tracking</span>';
    }
    
    // Start tracking if it was active
    if (trackingStates[qrId] && trackingStates[qrId].isTracking) {
        startTrackingForQR(qrId);
    }
}

// Add marker to map
function addMarkerToMap(qrId, lat, lng, title) {
    const position = { lat: parseFloat(lat), lng: parseFloat(lng) };
    
    // Remove existing marker if any
    if (markers[qrId]) {
        markers[qrId].setMap(null);
    }
    
    const marker = new google.maps.Marker({
        position: position,
        map: map,
        title: title,
        animation: google.maps.Animation.DROP,
        icon: {
            url: 'https://maps.google.com/mapfiles/ms/icons/red-dot.png',
            scaledSize: new google.maps.Size(32, 32)
        }
    });
    
    const infoWindow = new google.maps.InfoWindow({
        content: `<div><strong>${title}</strong><br>QR Code Location<br>Lat: ${lat}<br>Lng: ${lng}</div>`
    });
    
    marker.addListener('click', () => {
        infoWindow.open(map, marker);
    });
    
    markers[qrId] = marker;
}

// Update location display in tracking list
function updateLocationDisplay(qrId, lat, lng, locationName) {
    const locationElement = document.getElementById(`location-${qrId}`);
    if (locationElement) {
        locationElement.textContent = locationName || `${lat}, ${lng}`;
    }
}

// Update QR location display in QR code section
function updateQRLocationDisplay(qrId, lat, lng, locationName) {
    const qrLocationElement = document.getElementById(`qr-location-${qrId}`);
    if (qrLocationElement) {
        qrLocationElement.textContent = locationName || `${lat}, ${lng}`;
    }
}

// Update current location info
function updateCurrentLocationInfo(lat, lng) {
    const locationInfo = document.getElementById('current-location-info');
    if (locationInfo) {
        locationInfo.innerHTML = `
            <p><strong>Latitude:</strong> ${lat.toFixed(6)}</p>
            <p><strong>Longitude:</strong> ${lng.toFixed(6)}</p>
            <p><strong>Last Updated:</strong> ${new Date().toLocaleTimeString()}</p>
            <a href="https://www.google.com/maps?q=${lat},${lng}" target="_blank" class="btn btn-sm btn-outline-primary">
                <i class="fas fa-external-link-alt me-1"></i>Open in Google Maps
            </a>
        `;
    }
}

// Update active tracking list in modal
function updateActiveTrackingList() {
    const activeTrackingList = document.getElementById('active-tracking-list');
    if (!activeTrackingList) return;
    
    const activeQRCodes = Object.keys(trackingStates).filter(qrId => trackingStates[qrId].isTracking && userQrIds.has(Number(qrId)));
    
    if (activeQRCodes.length === 0) {
        activeTrackingList.innerHTML = '<p class="text-muted">No active tracking</p>';
        return;
    }
    
    let html = '';
    activeQRCodes.forEach(qrId => {
        const qrCode = trackingStates[qrId].qrCode || qrId;
        const locationElement = document.getElementById(`location-${qrId}`);
        const location = locationElement ? locationElement.textContent : 'Getting location...';
        
        html += `
            <div class="mb-2 p-2 border rounded bg-light">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <strong>${qrCode}</strong>
                        <div class="text-muted small">${location}</div>
                    </div>
                    <span class="badge bg-success">Active</span>
                </div>
            </div>
        `;
    });
    
    activeTrackingList.innerHTML = html;
}

// Track location for specific QR code
function trackLocation(qrId, qrCode) {
    currentTrackingQR = qrId;
    
    // Update tracking state
    trackingStates[qrId] = { isTracking: true, qrCode: qrCode };
    saveTrackingStates();
    
    // Update status
    const statusElement = document.getElementById(`status-${qrId}`);
    if (statusElement) {
        statusElement.innerHTML = '<span class="badge bg-success">Live Tracking</span>';
    }
    
    // Show tracking modal
    const modal = new bootstrap.Modal(document.getElementById('gpsTrackingModal'));
    modal.show();
    
    // Initialize tracking map
    setTimeout(() => {
        initTrackingMap();
        startTrackingForQR(qrId);
        updateActiveTrackingList();
    }, 500);
}

// Start tracking for specific QR code
function startTrackingForQR(qrId) {
    if (!navigator.geolocation) {
        alert('Geolocation is not supported by this browser.');
        return;
    }
    
    // Get current position
    navigator.geolocation.getCurrentPosition(
        (position) => {
            const lat = position.coords.latitude;
            const lng = position.coords.longitude;
            
            // Update all location displays
            updateLocationDisplay(qrId, lat, lng);
            updateQRLocationDisplay(qrId, lat, lng);
            
            // Update tracking map if open
            if (trackingMap) {
                const location = { lat: lat, lng: lng };
                trackingMap.setCenter(location);
                
                // Add or update marker
                if (markers[`tracking-${qrId}`]) {
                    markers[`tracking-${qrId}`].setPosition(location);
                } else {
                    const marker = new google.maps.Marker({
                        position: location,
                        map: trackingMap,
                        title: `QR Code ${qrId}`,
                        animation: google.maps.Animation.BOUNCE,
                        icon: {
                            url: 'https://maps.google.com/mapfiles/ms/icons/blue-dot.png',
                            scaledSize: new google.maps.Size(32, 32)
                        }
                    });
                    markers[`tracking-${qrId}`] = marker;
                }
                
                // Update location info
                updateCurrentLocationInfo(lat, lng);
                updateActiveTrackingList();
            }
            
            // Save location to database
            saveLocationToDatabase(qrId, lat, lng);
            // Update main map live markers
            updateMainMapLiveMarkers();
            
            // Start continuous tracking
            startContinuousTracking(qrId);
        },
        (error) => {
            console.error('Error getting location:', error);
            alert('Error getting location. Please check your browser permissions.');
        }
    );
}

// Initialize tracking map
function initTrackingMap() {
    const defaultLocation = { lat: 20.5937, lng: 78.9629 };
    trackingMap = new google.maps.Map(document.getElementById('tracking-map'), {
        zoom: 15,
        center: defaultLocation,
        mapTypeId: google.maps.MapTypeId.ROADMAP
    });
    // Remove all previous modal markers
    if (window.modalTrackingMarkers) {
        window.modalTrackingMarkers.forEach(marker => marker.setMap(null));
    }
    window.modalTrackingMarkers = [];
    // Only add marker for currentTrackingQR
    if (currentTrackingQR && markers[currentTrackingQR]) {
        const position = markers[currentTrackingQR].getPosition();
        const modalMarker = new google.maps.Marker({
            position: position,
            map: trackingMap,
            title: `QR Code ${currentTrackingQR}`,
            icon: {
                url: 'https://maps.google.com/mapfiles/ms/icons/blue-dot.png',
                scaledSize: new google.maps.Size(40, 40)
            },
            animation: google.maps.Animation.BOUNCE
        });
        window.modalTrackingMarkers.push(modalMarker);
        trackingMap.setCenter(position);
    }
    drawTrackingArrows();
}

// Start live location tracking
function startLiveTracking() {
    if (currentTrackingQR) {
        startTrackingForQR(currentTrackingQR);
    }
}

// Start continuous location tracking
function startContinuousTracking(qrId) {
    // Clear existing interval for this QR
    if (locationUpdateInterval) {
        clearInterval(locationUpdateInterval);
    }
    
    locationUpdateInterval = setInterval(() => {
        navigator.geolocation.getCurrentPosition(
            (position) => {
                const lat = position.coords.latitude;
                const lng = position.coords.longitude;
                
                // Update all location displays
                updateLocationDisplay(qrId, lat, lng);
                updateQRLocationDisplay(qrId, lat, lng);
                
                // Update marker position on main map
                if (markers[qrId]) {
                    markers[qrId].setPosition({ lat: lat, lng: lng });
                }
                
                // Update marker position on tracking map
                if (markers[`tracking-${qrId}`]) {
                    markers[`tracking-${qrId}`].setPosition({ lat: lat, lng: lng });
                }
                
                // Update location info if tracking modal is open
                if (trackingMap) {
                    updateCurrentLocationInfo(lat, lng);
                    updateActiveTrackingList();
                }
                
                // Save location to database
                saveLocationToDatabase(qrId, lat, lng);
                
                // Call drawTrackingArrows after updating marker positions
                drawTrackingArrows();
            },
            (error) => {
                console.error('Error updating location:', error);
            }
        );
    }, 10000); // Update every 10 seconds
}

// Stop live tracking
function stopLiveTracking() {
    if (locationUpdateInterval) {
        clearInterval(locationUpdateInterval);
        locationUpdateInterval = null;
    }
    
    if (currentTrackingQR) {
        const statusElement = document.getElementById(`status-${currentTrackingQR}`);
        if (statusElement) {
            statusElement.innerHTML = '<span class="badge bg-secondary">Not Tracking</span>';
        }
        
        // Update tracking state
        trackingStates[currentTrackingQR] = { isTracking: false };
        saveTrackingStates();
        
        // Stop marker animation
        if (markers[`tracking-${currentTrackingQR}`]) {
            markers[`tracking-${currentTrackingQR}`].setAnimation(null);
        }
        
        // Update active tracking list
        updateActiveTrackingList();
        // Update main map live markers
        updateMainMapLiveMarkers();
    }
}

// Stop location sharing
function stopLocationSharing(qrId) {
    // Stop tracking if this QR is currently being tracked
    if (currentTrackingQR === qrId) {
        stopLiveTracking();
    }
    
    // Update tracking state
    trackingStates[qrId] = { isTracking: false };
    saveTrackingStates();
    
    // Update status
    const statusElement = document.getElementById(`status-${qrId}`);
    if (statusElement) {
        statusElement.innerHTML = '<span class="badge bg-secondary">Not Tracking</span>';
    }
    
    // Update active tracking list
    updateActiveTrackingList();
    // Update main map live markers
    updateMainMapLiveMarkers();
    
    // Remove from database
    fetch('stop_location_sharing.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `qr_id=${qrId}&csrf_token=${encodeURIComponent('<?= $_SESSION['csrf_token'] ?>')}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Remove marker from map
            if (markers[qrId]) {
                markers[qrId].setMap(null);
                delete markers[qrId];
            }
            
            // Update location displays
            const locationElement = document.getElementById(`location-${qrId}`);
            if (locationElement) {
                locationElement.textContent = 'Location not available';
            }
            
            const qrLocationElement = document.getElementById(`qr-location-${qrId}`);
            if (qrLocationElement) {
                qrLocationElement.textContent = 'Not available';
            }
        }
    })
    .catch(error => console.error('Error stopping location sharing:', error));
}

// Add location manually
function addLocationManually(qrId, qrCode) {
    document.getElementById('manual_qr_id').value = qrId;
    
    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('manualLocationModal'));
    modal.show();
}

// Save location to database
function saveLocationToDatabase(qrId, lat, lng, locationName = '') {
    const formData = new FormData();
    formData.append('qr_id', qrId);
    formData.append('latitude', lat);
    formData.append('longitude', lng);
    formData.append('location_name', locationName);
    formData.append('csrf_token', '<?= $_SESSION['csrf_token'] ?>');
    
    fetch('save_location.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Add marker to main map
            addMarkerToMap(qrId, lat, lng, locationName || `QR Code ${qrId}`);
            updateLocationDisplay(qrId, lat, lng, locationName);
            updateQRLocationDisplay(qrId, lat, lng, locationName);
        }
    })
    .catch(error => console.error('Error saving location:', error));
}

// Handle manual location form submission
document.getElementById('manualLocationForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const qrId = document.getElementById('manual_qr_id').value;
    const lat = document.getElementById('latitude').value;
    const lng = document.getElementById('longitude').value;
    const locationName = document.getElementById('location_name').value;
    
    if (lat && lng) {
        saveLocationToDatabase(qrId, lat, lng, locationName);
        
        // Update UI immediately
        updateLocationDisplay(qrId, lat, lng, locationName);
        updateQRLocationDisplay(qrId, lat, lng, locationName);
        if (markers[qrId]) {
            markers[qrId].setPosition({ lat: parseFloat(lat), lng: parseFloat(lng) });
        }
        if (trackingMap && markers[`tracking-${qrId}`]) {
            markers[`tracking-${qrId}`].setPosition({ lat: parseFloat(lat), lng: parseFloat(lng) });
        }
        updateActiveTrackingList();
        updateMainMapLiveMarkers();
        
        // Close modal
        const modal = bootstrap.Modal.getInstance(document.getElementById('manualLocationModal'));
        modal.hide();
        
        // Reset form
        this.reset();
        
        // Show success message
        alert('Location saved successfully!');
    }
});

// Initialize map when page loads
document.addEventListener('DOMContentLoaded', function() {
    initMap();
    
    // Initialize active tracking list when GPS tracking modal opens
    const gpsTrackingModal = document.getElementById('gpsTrackingModal');
    if (gpsTrackingModal) {
        gpsTrackingModal.addEventListener('shown.bs.modal', function() {
            updateActiveTrackingList();
        });
    }
});
function startCamera() {
    const qrRegionId = "qr-reader";
    
    // Clear previous instance if exists
    if (qrScanner) {
        qrScanner.stop().catch(() => {});
    }

    qrScanner = new Html5Qrcode(qrRegionId);

    qrScanner.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: 250 },
        async (decodedText) => {
            try {
                // Stop scanner first
                await qrScanner.stop();
                document.getElementById(qrRegionId).innerHTML = "";

                // Extract numeric code
                let qrCodeValue = decodedText;
                const codeMatch = decodedText.match(/\d{16}/);
                if (codeMatch) {
                    qrCodeValue = codeMatch[0];
                }

                // Show loading state
                Swal.fire({
                    title: 'Processing QR Code',
                    allowOutsideClick: false,
                    didOpen: () => {
                        Swal.showLoading();
                    }
                });

                // Send to backend
                const response = await fetch("add_device.php", {
                    method: "POST",
                    headers: { 
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Requested-With": "XMLHttpRequest"
                    },
                    body: new URLSearchParams({
                        qr_code: qrCodeValue,
                        csrf_token: '<?= $_SESSION['csrf_token'] ?>'
                    })
                });

                // Check if response is JSON
                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    const text = await response.text();
                    throw new Error(text || 'Invalid server response');
                }

                const data = await response.json();

                if (!response.ok || !data.success) {
                    throw new Error(data.message || 'Request failed');
                }

                // Success
                Swal.fire({
                    icon: 'success',
                    title: 'Success!',
                    text: `QR Code ${data.code} added successfully`
                }).then(() => {
                    const modal = bootstrap.Modal.getInstance(document.getElementById('addDeviceModal'));
                    modal.hide();
                    location.reload();
                });

            } catch (error) {
                console.error('Error:', error);
                Swal.fire({
                    icon: 'error',
                    title: 'Error',
                    text: error.message || 'Failed to process QR code',
                }).then(() => {
                    // Restart scanner
                    startCamera();
                });
            }
        },
        (errorMessage) => {
            // Optional: Handle scanner errors
            console.log('Scanner error:', errorMessage);
        }
    ).catch(err => {
        console.error("Camera Error:", err);
        Swal.fire({
            icon: 'error',
            title: 'Camera Error',
            text: err.message || 'Could not access camera'
        });
    });
}
function stopCamera() {
    if (qrScanner) {
        qrScanner.stop().then(() => {
            document.getElementById("qr-reader").innerHTML = "";
        }).catch(e => {
            console.error("Stop error:", e);
        });
    }
}

// Modal event listeners with proper accessibility handling
const addDeviceModal = document.getElementById('addDeviceModal');
if (addDeviceModal) {
    addDeviceModal.addEventListener('shown.bs.modal', function() {
        startCamera();
    });
    addDeviceModal.addEventListener('hidden.bs.modal', function() {
        stopCamera();
    });
}
</script>
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<script>
document.getElementById('manualQrForm').addEventListener('submit', function (e) {
    e.preventDefault();

    const qrCode = document.getElementById('manual_qr').value;

    fetch('manual_qr_add.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'qr_code=' + encodeURIComponent(qrCode) + '&csrf_token=' + encodeURIComponent('<?= $_SESSION['csrf_token'] ?>')
    })
    .then(response => response.json())
    .then(data => {
        Swal.fire({
            icon: data.success ? 'success' : 'error',
           title: data.success ? 'Success' : 'Failed',
            text: data.message,
        }).then(() => {
            if (data.success) {
                location.reload();
            }
        });
    })
    .catch(error => {
       Swal.fire({
            icon: 'error',
            title: 'Error',
            text: error
        });
    });
});
async function scanQRCode(qrData) {
  try {
    const response = await fetch('add_device.php', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        qr_code: qrData,
        csrf_token: '<?= $_SESSION['csrf_token'] ?>'
      })
    });

    // First check if response exists
    if (!response) {
      throw new Error('No response from server');
    }

    // Check for empty response
    const text = await response.text();
    if (!text) {
      throw new Error('Empty response from server');
    }

    // Try to parse JSON
    const data = JSON.parse(text);
    
    if (!data.success) {
      throw new Error(data.error || 'Request failed');
    }
    
    return data;
    
  } catch (error) {
    console.error('Scan Error:', error);
    throw error; // Re-throw for handling in your UI
  }
}
// This JavaScript controls showing/hiding arrows and positioning them
document.addEventListener('DOMContentLoaded', function() {
    // When a tracking item is clicked or activated
    function activateTrackingItem(qrId) {
        // Remove active class from all items
        document.querySelectorAll('.tracking-item').forEach(item => {
            item.classList.remove('active');
        });
        
        // Hide all arrows
        document.querySelectorAll('.red-arrow').forEach(arrow => {
            arrow.style.display = 'none';
        });
        
        // Activate the selected one
        const item = document.getElementById(`tracking-${qrId}`);
        if (item) {
            item.classList.add('active');
            
            // Show and position the arrow
            const arrow = document.getElementById(`arrow-${qrId}`);
            if (arrow) {
                const itemRect = item.getBoundingClientRect();
                const mapElement = document.getElementById('map');
                const mapRect = mapElement.getBoundingClientRect();
                
                // Calculate positions
                const startX = itemRect.left - 10;
                const startY = itemRect.top + (itemRect.height / 2);
                const endX = mapRect.right - 10;
                const endY = mapRect.top + (mapRect.height * 0.25); // Adjust this for multiple markers
                
                // Set arrow position and rotation
                const length = Math.sqrt(Math.pow(endX - startX, 2) + Math.pow(endY - startY, 2));
                const angle = Math.atan2(endY - startY, endX - startX) * 180 / Math.PI;
                
                arrow.style.width = `${length}px`;
                arrow.style.left = `${startX}px`;
                arrow.style.top = `${startY}px`;
                arrow.style.transform = `rotate(${angle}deg)`;
                arrow.style.transformOrigin = 'left center';
                arrow.style.display = 'block';
            }
        }
    }
    
    // Example of how to activate an item (you would call this when tracking starts)
    // activateTrackingItem('123'); // Replace with actual QR ID
    
    // For demo purposes - add click handlers to show arrows
    document.querySelectorAll('.tracking-item').forEach(item => {
        item.addEventListener('click', function() {
            const qrId = this.getAttribute('data-qr-id');
            activateTrackingItem(qrId);
        });
    });
    
    // Automatically show arrows for active tracking items
    function updateTrackingArrows() {
        document.querySelectorAll('.tracking-item').forEach(item => {
            const qrId = item.getAttribute('data-qr-id');
            const statusElement = document.getElementById(`status-${qrId}`);
            
            if (statusElement && statusElement.textContent.includes('Tracking')) {
                activateTrackingItem(qrId);
            }
        });
    }
    
    // Call this when you update tracking status
    updateTrackingArrows();
});

// In JS, create a set of allowed QR IDs for this user
const userQrIds = new Set([<?php echo implode(',', array_map(function($qr){return $qr['id'];}, $qr_codes)); ?>]);

// Update all JS loops that process QR codes to check if userQrIds.has(qrId)
// For example, in loadTrackingStates, updateActiveTrackingList, drawTrackingArrows, etc.
// Example for drawTrackingArrows:
function drawTrackingArrows() {
    if (!trackingMap) return;
    if (window.trackingArrows) {
        window.trackingArrows.forEach(arrow => arrow.setMap(null));
    }
    window.trackingArrows = [];
    const center = trackingMap.getCenter();
    Object.keys(trackingStates).forEach(qrId => {
        if (!userQrIds.has(Number(qrId))) return;
        if (trackingStates[qrId].isTracking && markers[`tracking-${qrId}`]) {
            const marker = markers[`tracking-${qrId}`];
            const position = marker.getPosition();
            const line = new google.maps.Polyline({
                path: [center, position],
                geodesic: true,
                strokeColor: '#FF0000',
                strokeOpacity: 1.0,
                strokeWeight: 2,
                icons: [{
                    icon: {
                        path: google.maps.SymbolPath.FORWARD_CLOSED_ARROW,
                        scale: 3,
                        strokeColor: '#FF0000',
                        fillColor: '#FF0000',
                        fillOpacity: 1
                    },
                    offset: '100%'
                }],
                map: trackingMap
            });
            window.trackingArrows.push(line);
        }
    });
}

// Add this function to update main map markers for live tracking only
function updateMainMapLiveMarkers() {
    if (!map) return;
    // Remove all existing live markers
    if (window.liveTrackingMarkers) {
        window.liveTrackingMarkers.forEach(marker => marker.setMap(null));
    }
    window.liveTrackingMarkers = [];
    
    Object.keys(trackingStates).forEach(qrId => {
        if (!userQrIds.has(Number(qrId))) return;
        if (trackingStates[qrId].isTracking && markers[qrId]) {
            const position = markers[qrId].getPosition();
            const liveMarker = new google.maps.Marker({
                position: position,
                map: map,
                title: `QR Code ${qrId}`,
                icon: {
                    url: 'https://maps.google.com/mapfiles/ms/icons/green-dot.png', // location icon
                    scaledSize: new google.maps.Size(40, 40)
                },
                animation: google.maps.Animation.DROP
            });
            window.liveTrackingMarkers.push(liveMarker);
        }
    });
}

// Call updateMainMapLiveMarkers after any tracking state change, after loading locations, and after live tracking updates
// Example: after startTrackingForQR, stopLiveTracking, stopLocationSharing, manual location update, and after page load
</script>

</body>
</html>
