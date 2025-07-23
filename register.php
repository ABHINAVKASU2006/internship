<?php
session_start();
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
require 'vendor/autoload.php';
define('ADMIN_SECRET', 'AddWise');

function sendOTP($recipientEmail, $otp) {
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'abhinavsaireddykasu@gmail.com';
        $mail->Password   = 'qaiv sopm azoz ijeg';
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;
        $mail->setFrom('abhinavsaireddykasu@gmail.com', 'My PHP App');
        $mail->addAddress($recipientEmail);
        $mail->isHTML(true);
        $mail->Subject = 'Your OTP Code';
        $mail->Body    = "Your One-Time Password (OTP) is: <b>$otp</b>. It is valid for 10 minutes.";
        $mail->AltBody = "Your OTP is: $otp";
        $mail->send();
        return true;
    } catch (Exception $e) {
        return false;
    }
}

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email'])) {
   
    if ($_POST['role'] === 'admin') {
        if (!isset($_POST['admin_code']) || $_POST['admin_code'] !== ADMIN_SECRET) {
            $_SESSION['signup_error'] = "Invalid admin secret code.";
            header("Location: index3.php");
            exit();
        }
    }

    $otp = rand(100000, 999999);
    $_SESSION['full_name'] = $_POST['name'] ?? '';
    $_SESSION['email'] = $_POST['email'];
    $_SESSION['mobile'] = $_POST['mobile'] ?? '';
    $_SESSION['age'] = $_POST['age'] ?? '';
    $_SESSION['gender'] = $_POST['gender'] ?? '';
    $_SESSION['role'] = $_POST['role'] ?? 'user';
    $_SESSION['password'] = password_hash($_POST['password'], PASSWORD_DEFAULT);
    $_SESSION['otp'] = (string)$otp;
    $_SESSION['otp_expiry'] = time() + 600; 

   
    $_SESSION['registration_in_progress'] = true;  

    if (sendOTP($_SESSION['email'], $otp)) {
     
        header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
        header("Cache-Control: post-check=0, pre-check=0", false);
        header("Pragma: no-cache");
        header("Location: verify_otp.php");
        exit();
    } else {
        unset($_SESSION['registration_in_progress']);  
        $_SESSION['signup_error'] = "❌ Failed to send OTP. Check SMTP setup.";
        header("Location: index3.php");
        exit();
    }
} else { 
   
    $_SESSION['signup_error'] = "Invalid access method.";
    header("Location: index3.php");
    exit();
}
?>
