<?php
session_start();
require 'dbconnect.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: index3.php");
    exit();
}

if (
    !isset($_POST['otp_input'], $_SESSION['otp'], $_SESSION['full_name'], $_SESSION['email'],
        $_SESSION['mobile'], $_SESSION['age'], $_SESSION['gender'], $_SESSION['role'], $_SESSION['password'], $_SESSION['otp_expiry'])
) {
    $_SESSION['otp_error'] = "Session expired. Please restart registration.";
    header("Location: verify_otp.php");
    exit();
}

if (time() > $_SESSION['otp_expiry']) {
    unset($_SESSION['otp'], $_SESSION['otp_expiry'], $_SESSION['registration_in_progress']);
    $_SESSION['otp_error'] = "OTP expired. Please register again.";
    header("Location: verify_otp.php");
    exit();
}


$enteredOTP = trim((string)$_POST['otp_input']);
$correctOTP = (string)$_SESSION['otp'];

error_log("Session OTP: " . $correctOTP);
error_log("Entered OTP: " . $enteredOTP);


$full_name = $_SESSION['full_name'];
$email = $_SESSION['email'];
$mobile = $_SESSION['mobile'];
$age = $_SESSION['age'];
$gender = $_SESSION['gender'];
$role = $_SESSION['role'];
$password = $_SESSION['password'];
$is_verified = 1;

if ($enteredOTP === $correctOTP) {
    
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows === 0) {
        $insert = $conn->prepare("INSERT INTO users (full_name, email, mobile, age, gender, role, password, is_verified)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        $insert->bind_param("sssssssi", $full_name, $email, $mobile, $age, $gender, $role, $password, $is_verified);

        if (!$insert->execute()) {
            error_log("Database error: " . $insert->error);
            $_SESSION['otp_error'] = "Registration failed. Please try again.";
            header("Location: verify_otp.php");
            exit();
        }
    }

   
    $_SESSION['otp_verified'] = true;
    unset(
        $_SESSION['otp'],
        $_SESSION['otp_expiry'],
        $_SESSION['registration_in_progress'],
        $_SESSION['full_name'],
        $_SESSION['mobile'],
        $_SESSION['age'],
        $_SESSION['gender'],
        $_SESSION['password']
    );
 
    $_SESSION['show_alert'] = $stmt->num_rows === 0 
        ? "OTP verified successfully! You can now log in." 
        : "OTP verified! User already exists.";

    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Cache-Control: post-check=0, pre-check=0", false);
    header("Pragma: no-cache");
    header("Location: index3.php");
    exit();
} else {
    $_SESSION['otp_error'] = "❌ Incorrect OTP. Please try again.";
    header("Location: verify_otp.php");
    exit();
}
?>
