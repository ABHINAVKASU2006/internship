<?php
session_start();
require 'dbconnect.php';

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

if (isset($_SESSION['is_logged_in'])) {
    header("Location: " . ($_SESSION['role'] === 'Admin' ? 'admin_dashboard.php' : 'user_dashboard.php'));
    exit();
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $role = ucfirst(strtolower($_POST['role'] ?? 'User'));

    if (empty($email) || empty($password) || empty($role)) {
        $_SESSION['login_error'] = "All fields are required.";
        header("Location: index3.php");
        exit();
    }

    $stmt = $conn->prepare("SELECT id, full_name, email, password, role FROM users WHERE email = ? AND role = ? AND is_verified = 1");
    $stmt->bind_param("ss", $email, $role);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result && $result->num_rows === 1) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['password'])) {
          
            session_regenerate_id(true); 
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['is_logged_in'] = true;
            $_SESSION['LAST_ACTIVITY'] = time(); 

            header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
            header("Cache-Control: post-check=0, pre-check=0", false);
            header("Pragma: no-cache");
            header("Location: " . ($_SESSION['role'] === 'Admin' ? 'admin_dashboard.php' : 'user_dashboard.php'));
            exit();
        } else {
            $_SESSION['login_error'] = "Incorrect password.";
        }
    } else {
        $_SESSION['login_error'] = "User not found, not verified, or role mismatch.";
    }
    
    header("Location: index3.php");
    exit();
} else {
    $_SESSION['login_error'] = "Invalid request.";
    header("Location: index3.php");
    exit();
}
?>
 