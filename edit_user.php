<?php
// Include comprehensive protection
require_once 'protection.php';

// Additional admin-specific checks for user editing
if ($_SESSION['role'] !== 'Admin' && $_SESSION['role'] !== 'SuperAdmin') {
    SecurityMiddleware::logSecurityEvent('Unauthorized user edit attempt', "User: {$_SESSION['user_id']}, Role: {$_SESSION['role']}", 'WARNING');
    SecurityMiddleware::secureRedirect('index3.php');
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require 'dbconnect.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'Admin') {
    header("Location: index3.php");
    exit();
}

if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    header("Location: admin_dashboard.php");
    exit();
}

$user_id = intval($_GET['id']);
$success = $error = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $full_name = trim($_POST['full_name']);
    $email = trim($_POST['email']);
    $mobile = trim($_POST['mobile']);
    $age = intval($_POST['age']);
    $gender = $_POST['gender'];
    $role = $_POST['role'];
    $is_verified = isset($_POST['is_verified']) ? 1 : 0;

    if ($full_name && $email && $mobile && $age && $gender && $role) {
        $stmt = $conn->prepare("UPDATE users SET full_name=?, email=?, mobile=?, age=?, gender=?, role=?, is_verified=? WHERE id=?");
        $stmt->bind_param("ssssssii", $full_name, $email, $mobile, $age, $gender, $role, $is_verified, $user_id);

        if ($stmt->execute()) {
            $success = "User updated successfully!";
        } else {
            $error = "Failed to update user. Email may already exist.";
        }
    } else {
        $error = "All fields are required.";
    }
}

$stmt = $conn->prepare("SELECT full_name, email, mobile, age, gender, role, is_verified FROM users WHERE id=?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if (!$user) {
    header("Location: admin_dashboard.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Edit User</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
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
            min-height: 100vh;
            background: linear-gradient(120deg, var(--accent) 0%, var(--secondary) 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .edit-card {
            background: var(--white);
            backdrop-filter: blur(10px);
            border-radius: 22px;
            box-shadow: var(--shadow);
            border: 1px solid var(--secondary);
            padding: 40px 35px;
            max-width: 500px;
            width: 100%;
            margin: 60px auto;
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .edit-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(56, 189, 248, 0.18);
        }
        .edit-title {
            color: var(--primary);
            font-weight: 700;
            margin-bottom: 2rem;
            font-size: 2.1rem;
            letter-spacing: 0.5px;
            text-align: center;
        }
        .alert {
            border-radius: 12px;
            padding: 15px;
            margin-bottom: 25px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-label {
            color: var(--teal);
            font-weight: 600;
            margin-bottom: 8px;
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
        .form-check-input:checked {
            background-color: var(--primary);
            border-color: var(--primary);
        }
        .btn-save {
            background: linear-gradient(45deg, var(--primary), var(--teal));
            color: var(--white);
            border: none;
            border-radius: 12px;
            padding: 14px;
            font-size: 18px;
            font-weight: 600;
            letter-spacing: 0.5px;
            transition: all 0.3s;
            box-shadow: 0 6px 15px rgba(56, 189, 248, 0.18);
            width: 100%;
        }
        .btn-save:hover {
            background: linear-gradient(45deg, var(--teal), var(--primary));
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(56, 189, 248, 0.22);
        }
        .btn-back {
            display: block;
            text-align: center;
            color: var(--primary);
            font-weight: 600;
            margin-top: 20px;
            text-decoration: none;
            transition: color 0.3s;
        }
        .btn-back:hover {
            color: var(--teal);
            text-decoration: underline;
        }
        @media (max-width: 600px) {
            .edit-card {
                padding: 25px 10px;
            }
            .edit-title {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
<div class="edit-card">
    <h2 class="edit-title">Edit User</h2>
    
    <?php if ($success): ?>
        <div class="alert alert-success"><?= $success ?></div>
    <?php elseif ($error): ?>
        <div class="alert alert-danger"><?= $error ?></div>
    <?php endif; ?>
    
    <form method="post" autocomplete="off">
        <div class="form-group">
            <label class="form-label">Full Name</label>
            <input type="text" name="full_name" class="form-control" 
                   value="<?= htmlspecialchars($user['full_name']) ?>" required>
        </div>
        
        <div class="form-group">
            <label class="form-label">Email</label>
            <input type="email" name="email" class="form-control" 
                   value="<?= htmlspecialchars($user['email']) ?>" required>
        </div>
        
        <div class="form-group">
            <label class="form-label">Mobile</label>
            <input type="tel" name="mobile" class="form-control" 
                   value="<?= htmlspecialchars($user['mobile']) ?>" required 
                   pattern="[0-9]{10}" title="10-digit mobile number">
        </div>
        
        <div class="form-group">
            <label class="form-label">Age</label>
            <input type="number" name="age" class="form-control" 
                   value="<?= htmlspecialchars($user['age']) ?>" min="1" max="120" required>
        </div>
        
        <div class="form-group">
            <label class="form-label">Gender</label>
            <select name="gender" class="form-select" required>
                <option value="">Select Gender</option>
                <option <?= $user['gender'] == 'Male' ? 'selected' : '' ?>>Male</option>
                <option <?= $user['gender'] == 'Female' ? 'selected' : '' ?>>Female</option>
                <option <?= $user['gender'] == 'Other' ? 'selected' : '' ?>>Other</option>
            </select>
        </div>
        
        <div class="form-group">
            <label class="form-label">Role</label>
            <select name="role" class="form-select" required>
                <option value="User" <?= $user['role'] == 'User' ? 'selected' : '' ?>>User</option>
                <option value="Admin" <?= $user['role'] == 'Admin' ? 'selected' : '' ?>>Admin</option>
            </select>
        </div>
        
        <div class="form-group">
            <div class="form-check">
                <input class="form-check-input" type="checkbox" name="is_verified" 
                       id="is_verified" <?= $user['is_verified'] ? 'checked' : '' ?>>
                <label class="form-check-label" for="is_verified">
                    Verified Account
                </label>
            </div>
        </div>
        
        <button type="submit" class="btn btn-save">Save Changes</button>
        <a href="admin_dashboard.php" class="btn-back">← Back to Dashboard</a>
    </form>
</div>

<script>
    history.pushState(null, null, location.href);
    window.onpopstate = function() { history.go(1); };
    window.addEventListener('pageshow', function(event) {
        if (event.persisted || (window.performance && window.performance.navigation.type === 2)) {
            window.location.reload();
        }
    });
</script>
</body>
</html>
