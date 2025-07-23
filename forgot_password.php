<?php
session_start();
require 'dbconnect.php';
if (isset($_SESSION['password_reset_complete']) && $_SESSION['password_reset_complete'] === true) {
    header("Location: index.php");
    exit();
}
// If user is already logged in, redirect to dashboard
if (isset($_SESSION['is_logged_in'])) {
    if ($_SESSION['role'] === 'Admin') {
        header("Location: admin_dashboard.php");
    } else if ($_SESSION['role'] === 'User') {
        header("Location: user_dashboard.php");
    }
    exit();
}

unset($_SESSION['reset_otp_verified']);
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

$email_val = isset($_GET['email']) ? htmlspecialchars($_GET['email']) : '';
$role_val = isset($_GET['role']) ? htmlspecialchars($_GET['role']) : '';

define('ADMIN_SECRET', 'AddWise');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email'], $_POST['role'])) {
    $email = trim($_POST['email']);
    $role = trim($_POST['role']);
    $admin_code = isset($_POST['admin_code']) ? trim($_POST['admin_code']) : '';

    $role_db = ucfirst(strtolower($role));

    $stmt = $conn->prepare("SELECT id, role FROM users WHERE email = ? AND is_verified = 1");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        $actual_role = $user['role'];

        if ($actual_role !== $role_db) {
            $_SESSION['reset_error'] = "The email exists, but not with the selected role. ";
        } else {
            if ($role_db === 'Admin') {
                if (empty($admin_code) || $admin_code !== ADMIN_SECRET) {
                    $_SESSION['reset_error'] = "Invalid admin secret code.";
                } else {
                    generateAndSendOTP($email, $role_db);
                }
            } else {
                generateAndSendOTP($email, $role_db);
            }
        }
    } else {
        $_SESSION['reset_error'] = "No verified account found with this email.";
    }
}

function generateAndSendOTP($email, $role_db) {
    $otp = rand(100000, 999999);
    $_SESSION['reset_email'] = $email;
    $_SESSION['reset_role'] = $role_db;
    $_SESSION['reset_otp'] = $otp;
    $_SESSION['reset_otp_expiry'] = time() + 600;

    require 'mailer.php';
    if (sendOTP($email, $otp, $role_db)) {
        header("Location: reset_password_otp.php");
        exit();
    } else {
        $_SESSION['reset_error'] = "Failed to send OTP. Please try again.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #38bdf8;        /* Light Blue */
            --secondary: #e0f2fe;      /* Very light blue */
            --accent: #fbbf24;         /* Soft yellow accent */
            --teal: #0ea5e9;           /* Deeper blue for contrast */
            --dark: #1e293b;           /* Dark blue-gray for text */
            --white: #ffffff;
            --light-gray: #f8fafc;
            --shadow: 0 12px 30px rgba(56, 189, 248, 0.10);
        }
        
        body {
            background: linear-gradient(135deg, var(--primary), var(--teal), var(--secondary));
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .password-container {
            background: var(--white);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px 35px;
            max-width: 500px;
            width: 100%;
            box-shadow: var(--shadow);
            border: 1px solid var(--secondary);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .password-container:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(56, 189, 248, 0.18);
        }
        
        .password-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .password-header h2 {
            color: var(--primary);
            font-weight: 700;
            margin-bottom: 10px;
            font-size: 32px;
            letter-spacing: 0.5px;
        }
        
        .role-badge {
            background: linear-gradient(45deg, var(--primary), var(--teal));
            color: var(--white);
            padding: 8px 25px;
            border-radius: 50px;
            font-size: 16px;
            display: inline-block;
            margin-bottom: 25px;
            box-shadow: 0 4px 15px rgba(56, 189, 248, 0.12);
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        .form-label {
            color: var(--teal);
            font-weight: 600;
            margin-bottom: 10px;
            font-size: 16px;
        }
        
        .form-control {
            background: var(--secondary);
            border: 2px solid var(--teal);
            border-radius: 12px;
            padding: 14px 20px;
            color: var(--dark);
            font-size: 16px;
            transition: all 0.3s;
            box-shadow: inset 0 2px 5px rgba(0,0,0,0.05);
        }
        
        .form-control:focus {
            background: var(--white);
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
            outline: none;
        }
        
        .form-control::placeholder {
            color: #7a9e94;
        }
        
        .btn-primary {
            background: linear-gradient(45deg, var(--primary), var(--teal));
            border: none;
            border-radius: 12px;
            padding: 14px;
            font-size: 18px;
            font-weight: 600;
            letter-spacing: 0.5px;
            transition: all 0.3s;
            box-shadow: 0 6px 15px rgba(56, 189, 248, 0.18);
        }
        
        .btn-primary:hover {
            background: linear-gradient(45deg, var(--teal), var(--primary));
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(56, 189, 248, 0.22);
        }
        
        .btn-primary:active {
            transform: translateY(0);
        }
        
        .back-link {
            display: block;
            text-align: center;
            color: var(--primary);
            font-weight: 500;
            margin-top: 20px;
            text-decoration: none;
            transition: color 0.3s;
        }
        
        .back-link:hover {
            color: var(--teal);
            text-decoration: underline;
        }
        
        .alert {
            border-radius: 12px;
            padding: 15px;
            margin-bottom: 25px;
        }
        
        .admin-code-container {
            background: rgba(14, 165, 233, 0.08); /* var(--teal) with opacity */
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 25px;
            border-left: 4px solid var(--primary);
        }
        
        .form-text {
            color: #5d8a7f;
            font-size: 14px;
            margin-top: 8px;
        }
        
        @media (max-width: 576px) {
            .password-container {
                padding: 30px 25px;
            }
            
            .password-header h2 {
                font-size: 28px;
            }
        }
    </style>
</head>
<body>
    <div class="password-container">
        <div class="password-header">
            <h2>Reset Password</h2>
            <div class="role-badge">Role: <?= htmlspecialchars(ucfirst($role_val)) ?></div>
        </div>
        
        <?php if (isset($_SESSION['reset_error'])): ?>
            <div class="alert alert-danger"><?= $_SESSION['reset_error']; unset($_SESSION['reset_error']); ?></div>
        <?php endif; ?>
        
        <form method="POST">
            <input type="hidden" name="role" value="<?= $role_val ?>">
            
            <div class="form-group">
                <label class="form-label">Registered Email</label>
                <input type="email" class="form-control" name="email" required 
                       value="<?= $email_val ?>" readonly>
            </div>
            
            <?php if (strtolower($role_val) === 'admin'): ?>
            <div class="admin-code-container">
                <div class="form-group">
                    <label class="form-label">Admin Secret Code</label>
                    <input type="password" class="form-control" name="admin_code" 
                           placeholder="Enter admin secret code" required>
                    <div class="form-text">Required for admin password reset</div>
                </div>
            </div>
            <?php endif; ?>
            
            <button type="submit" class="btn btn-primary w-100">Send OTP</button>
            
            <a href="index3.php" class="back-link">← Back to Login</a>
        </form>
    </div>
    <script>
// Prevent back navigation
history.pushState(null, null, location.href);
window.onpopstate = function() {
    history.go(1);
};

// Force reload if page is restored from cache
window.addEventListener('pageshow', function(event) {
    if (event.persisted || performance.navigation.type === 2) {
        window.location.reload();
    }
});

 if (window.history && window.history.pushState) {
        window.history.pushState(null, null, window.location.href);
        window.onpopstate = function () {
            window.location.href = 'index.php';
        };
    }
</script>

</body>
</html>
