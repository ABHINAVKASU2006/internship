<?php
// Additional user-specific checks for profile viewing

session_start();
require 'dbconnect.php';
if (!in_array($_SESSION['role'], ['User', 'Admin', 'SuperAdmin'])) {
    SecurityMiddleware::logSecurityEvent('Unauthorized profile view attempt', "User: {$_SESSION['user_id']}, Role: {$_SESSION['role']}", 'WARNING');
    SecurityMiddleware::secureRedirect('index3.php');
}


if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'User') {
    header("Location: index3.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT full_name, email, mobile, age, gender FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>View Profile</title>
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
        .profile-card {
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
        .profile-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(56, 189, 248, 0.18);
        }
        .profile-title {
            color: var(--primary);
            font-weight: 700;
            margin-bottom: 2rem;
            font-size: 2.1rem;
            letter-spacing: 0.5px;
            text-align: center;
        }
        .profile-info {
            background: var(--secondary);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 25px;
            border-left: 4px solid var(--primary);
        }
        .info-item {
            display: flex;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--secondary);
        }
        .info-item:last-child {
            margin-bottom: 0;
            padding-bottom: 0;
            border-bottom: none;
        }
        .info-label {
            flex: 0 0 140px;
            font-weight: 600;
            color: var(--primary);
        }
        .info-value {
            flex: 1;
            color: var(--dark);
        }
        .btn-edit {
            background: linear-gradient(45deg, var(--primary), var(--teal));
            color: var(--white);
            border: none;
            border-radius: 12px;
            padding: 12px;
            font-weight: 600;
            font-size: 1.1rem;
            letter-spacing: 0.5px;
            transition: all 0.3s;
            box-shadow: 0 6px 15px rgba(56, 189, 248, 0.18);
            width: 100%;
        }
        .btn-edit:hover {
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
            .profile-card {
                padding: 25px 10px;
            }
            .info-item {
                flex-direction: column;
            }
            .info-label {
                margin-bottom: 5px;
            }
        }
    </style>
</head>
<body>
<div class="profile-card">
    <h2 class="profile-title">Your Profile</h2>
    <div class="profile-info">
        <div class="info-item">
            <div class="info-label">Full Name:</div>
            <div class="info-value"><?= htmlspecialchars($user['full_name']) ?></div>
        </div>
        <div class="info-item">
            <div class="info-label">Email:</div>
            <div class="info-value"><?= htmlspecialchars($user['email']) ?></div>
        </div>
        <div class="info-item">
            <div class="info-label">Mobile:</div>
            <div class="info-value"><?= htmlspecialchars($user['mobile']) ?></div>
        </div>
        <div class="info-item">
            <div class="info-label">Age:</div>
            <div class="info-value"><?= htmlspecialchars($user['age']) ?></div>
        </div>
        <div class="info-item">
            <div class="info-label">Gender:</div>
            <div class="info-value"><?= htmlspecialchars($user['gender']) ?></div>
        </div>
    </div>
    <a href="edit_profile_users.php" class="btn btn-edit">Edit Profile</a>
    <a href="user_dashboard.php" class="btn-back">← Back to Dashboard</a>
</div>
</body>
</html>
