<?php
// Enable error reporting
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Database configuration
$host = 'localhost';
$dbname = 'addwise';
$username = 'root';
$password = '123456'; 

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Include QR code library
require_once('phpqrcode/phpqrcode/qrlib.php');

// Function to generate random 16-digit code
function generateRandomCode() {
    $code = '';
    for ($i = 0; $i < 16; $i++) {
        $code .= (string)rand(0, 9);
    }
    return $code;
}

// Get active section from URL
$active_section = isset($_GET['section']) ? $_GET['section'] : 'dashboard';

// Process QR generation form
$qrCount = isset($_POST['qrCount']) ? (int)$_POST['qrCount'] : 0;
$qrError = '';

// Process QR deletion
if (isset($_GET['delete_id'])) {
    try {
        $stmt = $pdo->prepare("DELETE FROM qr_codes WHERE id = ?");
        $stmt->execute([$_GET['delete_id']]);
        $_SESSION['success'] = "QR code deleted successfully!";
        header("Location: superadmin_dashboard.php?section=qr_codes");
        exit;
    } catch (PDOException $e) {
        $qrError = "Error deleting QR code: " . $e->getMessage();
    }
}

// Generate new QR codes
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $qrCount > 0) {
    if ($qrCount < 1 || $qrCount > 100) {
        $qrError = "Please enter a number between 1 and 100.";
    } else {
        try {
            $pdo->beginTransaction();
            for ($i = 0; $i < $qrCount; $i++) {
                $code = generateRandomCode();
                ob_start();
                QRcode::png($code, null, QR_ECLEVEL_L, 6, 2);
                $imageString = ob_get_contents();
                ob_end_clean();
                $base64Image = base64_encode($imageString);

                // Save to database
                $stmt = $pdo->prepare("INSERT INTO qr_codes (code, image_data) VALUES (?, ?)");
                $stmt->execute([$code, $base64Image]);
            }
            $pdo->commit();
            $_SESSION['success'] = "$qrCount QR codes generated successfully!";
            header("Location: superadmin_dashboard.php?section=qr_codes");
            exit;
        } catch (PDOException $e) {
            $pdo->rollBack();
            $qrError = "Database error: " . $e->getMessage();
        }
    }
}

// Fetch all QR codes from database
$existingQrCodes = [];
try {
    $stmt = $pdo->query("SELECT id, code, image_data, created_at FROM qr_codes ORDER BY created_at DESC");
    $existingQrCodes = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $qrError = "Error loading QR codes: " . $e->getMessage();
}

// Fetch user statistics
$users_count = 0;
$admins_count = 0;
$all_users = [];
$all_admins = [];

try {
    // Total users
    $stmt = $pdo->query("SELECT COUNT(*) AS count FROM users WHERE role = 'User'");
    $users_count = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
    
    // Total admins
    $stmt = $pdo->query("SELECT COUNT(*) AS count FROM users WHERE role = 'Admin'");
    $admins_count = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
    
    // All users
    $stmt = $pdo->query("SELECT * FROM users WHERE role = 'User'");
    $all_users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // All admins
    $stmt = $pdo->query("SELECT * FROM users WHERE role = 'Admin'");
    $all_admins = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $qrError = "Error loading user data: " . $e->getMessage();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Superadmin Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --primary: #38bdf8;        /* Light Blue */
      --secondary: #e0f2fe;      /* Very light blue */
      --accent: #fbbf24;         /* Soft yellow accent */
      --teal: #0ea5e9;           /* Deeper blue for contrast */
      --dark: #1e293b;           /* Dark blue-gray for text */
      --danger: #e57373;
      --white: #ffffff;
      --light-gray: #f8fafc;
      --shadow: 0 12px 30px rgba(56, 189, 248, 0.10);
    }
    body {
      margin: 0;
      font-family: 'Segoe UI', Arial, sans-serif;
      background: var(--secondary);
      color: var(--dark);
    }
    .navbar {
      background: var(--primary);
      color: var(--white);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.7rem 2rem;
      position: sticky;
      top: 0;
      z-index: 100;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .navbar .logo {
      font-weight: 700;
      font-size: 1.4rem;
      letter-spacing: 1px;
      text-decoration: none;
      color: var(--white);
    }
    .navbar-links {
      display: flex;
      gap: 1.2rem;
      align-items: center;
    }
    .navbar-links a {
      color: var(--white);
      text-decoration: none;
      font-size: 1rem;
      font-weight: 500;
      padding: 0.5rem 1rem;
      border-radius: 4px;
      transition: background 0.2s, color 0.2s;
    }
    .navbar-links a.active, .navbar-links a:hover {
      background: var(--teal);
      color: var(--white);
    }
    .dashboard-container {
      max-width: 1200px;
      margin: 2rem auto;
      padding: 0 1rem;
    }
    .dashboard-header {
      display: flex;
      flex-wrap: wrap;
      gap: 1.5rem;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
    }
    .dashboard-header h1 {
      font-size: 2rem;
      font-weight: 700;
      color: var(--primary);
      margin: 0;
    }
    .superadmin-badge {
      background: var(--teal);
      color: var(--white);
      font-weight: 600;
      padding: 0.5rem 1.2rem;
      border-radius: 20px;
      font-size: 1rem;
      box-shadow: 0 2px 8px rgba(56,189,248,0.10);
    }
    .stats-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2.5rem;
    }
    .stat-card {
      background: var(--white);
      border-left: 4px solid var(--primary);
      border-radius: 10px;
      box-shadow: 0 3px 10px rgba(0,0,0,0.08);
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
    }
    .stat-label {
      font-size: 1rem;
      color: var(--dark);
      margin-bottom: 0.5rem;
      opacity: 0.8;
    }
    .stat-value {
      font-size: 2.2rem;
      font-weight: 700;
      color: var(--primary);
    }
    .action-section {
      background: var(--white);
      border-radius: 12px;
      box-shadow: 0 3px 12px rgba(0,0,0,0.08);
      padding: 1.5rem;
      margin-bottom: 2rem;
    }
    .section-title {
      font-size: 1.3rem;
      font-weight: 600;
      color: var(--primary);
      margin-bottom: 1.2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .qr-generator {
      display: flex;
      gap: 1rem;
      align-items: center;
      flex-wrap: wrap;
    }
    .qr-generator input {
      padding: 0.8rem 1rem;
      font-size: 1rem;
      border: 2px solid var(--teal);
      border-radius: 8px;
      width: 100px;
      text-align: center;
    }
    .btn {
      background: var(--primary);
      color: var(--white);
      border: none;
      padding: 0.8rem 1.5rem;
      font-size: 1rem;
      font-weight: 600;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
    }
    .btn:hover {
      background: var(--teal);
      color: var(--white);
      transform: translateY(-2px);
    }
    .btn-danger {
      background: var(--danger);
    }
    .qr-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 1.5rem;
      margin-top: 1.5rem;
    }
    .qr-card {
      background: var(--white);
      border-radius: 12px;
      box-shadow: 0 3px 10px rgba(0,0,0,0.08);
      padding: 1.2rem;
      text-align: center;
      position: relative;
      transition: transform 0.2s;
      border: 1px solid var(--secondary);
    }
    .qr-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 5px 15px rgba(56, 189, 248, 0.10);
    }
    .delete-qr {
      position: absolute;
      top: 8px;
      right: 8px;
      background: var(--danger);
      color: var(--white);
      border: none;
      border-radius: 50%;
      width: 26px;
      height: 26px;
      font-size: 16px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      opacity: 0.7;
      transition: opacity 0.2s;
    }
    .delete-qr:hover {
      opacity: 1;
    }
    .qr-image {
      width: 140px;
      height: 140px;
      margin: 0 auto 1rem auto;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .qr-image img {
      max-width: 100%;
      max-height: 100%;
    }
    .qr-code-text {
      font-family: monospace;
      font-size: 15px;
      color: var(--dark);
      word-break: break-all;
      font-weight: 600;
      margin: 0.5rem 0;
    }
    .qr-meta {
      font-size: 0.85rem;
      color: #777;
      margin-top: 0.3rem;
    }
    .alert {
      padding: 1rem;
      border-radius: 8px;
      margin-bottom: 1.5rem;
    }
    .alert-success {
      background: rgba(56,189,248,0.15);
      color: var(--dark);
      border: 1px solid rgba(56,189,248,0.3);
    }
    .alert-error {
      background: rgba(229,115,115,0.15);
      color: #b71c1c;
      border: 1px solid rgba(229,115,115,0.3);
    }
    .no-qr {
      text-align: center;
      padding: 2rem;
      color: #777;
      font-style: italic;
    }
    .data-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
    }
    .data-table th {
      background: var(--teal);
      color: var(--white);
      font-weight: 600;
      padding: 0.8rem;
      text-align: left;
    }
    .data-table td {
      padding: 0.8rem;
      border-bottom: 1px solid var(--secondary);
    }
    .data-table tr:hover {
      background-color: rgba(224,242,254,0.3);
    }
    @media (max-width: 768px) {
      .stats-cards {
        grid-template-columns: 1fr;
      }
      .qr-grid {
        grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
      }
      .navbar-links {
        flex-wrap: wrap;
        justify-content: center;
      }
    }
    .section-content {
      display: none;
    }
    .section-content.active {
      display: block;
    }
  </style>
</head>
<body>
  <!-- Navbar -->
  <nav class="navbar">
    <a href="#" class="logo">QR Management</a>
    <div class="navbar-links">
      <a href="?section=dashboard" class="<?= $active_section === 'dashboard' ? 'active' : '' ?>">Dashboard</a>
      <a href="?section=qr_codes" class="<?= $active_section === 'qr_codes' ? 'active' : '' ?>">QR Codes</a>
      <a href="?section=users" class="<?= $active_section === 'users' ? 'active' : '' ?>">Users</a>
      <a href="?section=admins" class="<?= $active_section === 'admins' ? 'active' : '' ?>">Admins</a>
      <a href="#">Reports</a>
      <a href="superadmin_logout.php">Logout</a>
    </div>
  </nav>

  <div class="dashboard-container">
    <?php if (isset($_SESSION['success'])): ?>
      <div class="alert alert-success">
        <?= $_SESSION['success'] ?>
        <?php unset($_SESSION['success']); ?>
      </div>
    <?php endif; ?>
    
    <?php if ($qrError): ?>
      <div class="alert alert-error">
        <?= $qrError ?>
      </div>
    <?php endif; ?>
    
    <!-- Dashboard Section -->
    <div class="section-content <?= $active_section === 'dashboard' ? 'active' : '' ?>">
      <div class="dashboard-header">
        <h1>Superadmin Dashboard</h1>
        <div class="superadmin-badge">Superadmin</div>
      </div>

      <div class="stats-cards">
        <div class="stat-card">
          <div class="stat-label">Total Users</div>
          <div class="stat-value"><?= $users_count ?></div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Admins</div>
          <div class="stat-value"><?= $admins_count ?></div>
        </div>
        <div class="stat-card">
          <div class="stat-label">QR Codes</div>
          <div class="stat-value"><?= count($existingQrCodes) ?></div>
        </div>
      </div>

      <!-- QR Generator Section -->
      <div class="action-section">
        <div class="section-title">
          <h2>QR Code Management</h2>
        </div>
        
        <form method="post" class="qr-generator">
          <input type="number" name="qrCount" min="1" max="100" required
                 value="<?= htmlspecialchars($qrCount) ?>" 
                 placeholder="Number">
          <button type="submit" class="btn">
            Generate QR Codes
          </button>
        </form>
      </div>
    </div>

    <!-- QR Codes Section -->
    <div class="section-content <?= $active_section === 'qr_codes' ? 'active' : '' ?>">
      <div class="dashboard-header">
        <h1>QR Code Management</h1>
      </div>
      
      <div class="action-section">
        <div class="qr-grid">
          <?php if (!empty($existingQrCodes)): ?>
            <?php foreach ($existingQrCodes as $qr): ?>
              <div class="qr-card">
                <a href="?section=qr_codes&delete_id=<?= $qr['id'] ?>" class="delete-qr" 
                   onclick="return confirm('Delete this QR code permanently?')">
                  &times;
                </a>
                <div class="qr-image">
                  <img src="data:image/png;base64,<?= $qr['image_data'] ?>" alt="QR Code">
                </div>
                <div class="qr-code-text"><?= htmlspecialchars($qr['code']) ?></div>
                <div class="qr-meta">
                  <?= date('M d, Y', strtotime($qr['created_at'])) ?>
                </div>
              </div>
            <?php endforeach; ?>
          <?php else: ?>
            <div class="no-qr">No QR codes found. Generate some using the form above.</div>
          <?php endif; ?>
        </div>
      </div>
    </div>

    <!-- Users Section -->
    <div class="section-content <?= $active_section === 'users' ? 'active' : '' ?>">
      <div class="dashboard-header">
        <h1>User Management</h1>
        <div class="superadmin-badge">Total Users: <?= $users_count ?></div>
      </div>
      
      <div class="action-section">
        <table class="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Full Name</th>
              <th>Email</th>
              <th>Mobile</th>
              <th>Role</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($all_users as $user): ?>
              <tr>
                <td><?= htmlspecialchars($user['id']) ?></td>
                <td><?= htmlspecialchars($user['full_name']) ?></td>
                <td><?= htmlspecialchars($user['email']) ?></td>
                <td><?= htmlspecialchars($user['mobile']) ?></td>
                <td><?= htmlspecialchars($user['role']) ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Admins Section -->
    <div class="section-content <?= $active_section === 'admins' ? 'active' : '' ?>">
      <div class="dashboard-header">
        <h1>Admin Management</h1>
        <div class="superadmin-badge">Total Admins: <?= $admins_count ?></div>
      </div>
      
      <div class="action-section">
        <table class="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Full Name</th>
              <th>Email</th>
              <th>Mobile</th>
              <th>Role</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($all_admins as $admin): ?>
              <tr>
                <td><?= htmlspecialchars($admin['id']) ?></td>
                <td><?= htmlspecialchars($admin['full_name']) ?></td>
                <td><?= htmlspecialchars($admin['email']) ?></td>
                <td><?= htmlspecialchars($admin['mobile']) ?></td>
                <td><?= htmlspecialchars($admin['role']) ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
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

  <script>
    // Confirm before deleting QR code
    document.querySelectorAll('.delete-qr').forEach(button => {
      button.addEventListener('click', function(e) {
        if (!confirm('Are you sure you want to delete this QR code?')) {
          e.preventDefault();
        }
      });
    });
  </script>
</body>
</html>
