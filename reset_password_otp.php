<?php
session_start();
require 'dbconnect.php';

if (!isset($_SESSION['reset_email'])) {
    header("Location: forgot_password.php");
    exit();
}

// Prevent returning after OTP verification
if (isset($_SESSION['reset_otp_verified'])) {
    header("Location: reset_password.php");
    exit();
}
// Prevent caching
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// Check if email is set in session
if (!isset($_SESSION['reset_email'])) {
    header("Location: forgot_password.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['otp'])) {
    $enteredOTP = trim($_POST['otp']);
    
    // Verify OTP
    if (isset($_SESSION['reset_otp'], $_SESSION['reset_otp_expiry']) && 
        $enteredOTP == $_SESSION['reset_otp'] && 
        time() < $_SESSION['reset_otp_expiry']) {
        
        header("Location: reset_password.php");
        exit();
    } else {
        $_SESSION['reset_error'] = "Invalid or expired OTP";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify OTP</title>
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
        
        .otp-container {
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
        
        .otp-container:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(56, 189, 248, 0.18);
        }
        
        .otp-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .otp-header h2 {
            color: var(--primary);
            font-weight: 700;
            margin-bottom: 10px;
            font-size: 32px;
            letter-spacing: 0.5px;
        }
        
        .email-display {
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
            text-align: center;
            letter-spacing: 5px;
            font-weight: bold;
        }
        
        .form-control:focus {
            background: var(--white);
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
            outline: none;
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
        
        .resend-link {
            display: block;
            text-align: center;
            color: var(--primary);
            font-weight: 500;
            margin-top: 20px;
            text-decoration: none;
            transition: color 0.3s;
        }
        
        .resend-link:hover {
            color: var(--teal);
            text-decoration: underline;
        }
        
        .alert {
            border-radius: 12px;
            padding: 15px;
            margin-bottom: 25px;
        }
        
        .otp-instructions {
            color: #5d8a7f;
            text-align: center;
            margin-bottom: 25px;
            font-size: 15px;
        }
        
        @media (max-width: 576px) {
            .otp-container {
                padding: 30px 25px;
            }
            
            .otp-header h2 {
                font-size: 28px;
            }
        }
    </style>
</head>
<body>
    <div class="otp-container">
        <div class="otp-header">
            <h2>Verify OTP</h2>
            <div class="email-display"><?= htmlspecialchars($_SESSION['reset_email']) ?></div>
        </div>
        
        <?php if (isset($_SESSION['reset_error'])): ?>
            <div class="alert alert-danger"><?= $_SESSION['reset_error']; unset($_SESSION['reset_error']); ?></div>
        <?php endif; ?>
        
        <p class="otp-instructions">Enter the 6-digit OTP sent to your email address</p>
        
        <form method="POST">
            <div class="form-group">
                <label class="form-label">OTP Code</label>
                <input type="text" class="form-control" name="otp" required 
                       maxlength="6" pattern="\d{6}" placeholder="••••••">
            </div>
            
            <button type="submit" class="btn btn-primary w-100">Verify OTP</button>
            
            <a href="forgot_password.php" class="resend-link">Resend OTP</a>
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
</script>

</body>
</html>
