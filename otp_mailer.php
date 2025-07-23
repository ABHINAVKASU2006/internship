<?php
session_start();

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';


header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
 
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
        $mail->Body    = "Your OTP is: <b>$otp</b> (valid for 10 minutes)";
        $mail->AltBody = "Your OTP is: $otp";

        $mail->send();
        return true;

    } catch (Exception $e) {
        
        return false;
    }
}


if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email'])) {
    $recipientEmail = trim($_POST['email']);
    if (!filter_var($recipientEmail, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['otp_error'] = "Invalid email address.";
        header("Location: index3.php");
        exit();
    }

    $otp = rand(100000, 999999);

    $_SESSION['otp'] = $otp;
    $_SESSION['email'] = $recipientEmail;
    $_SESSION['otp_expiry'] = time() + 600; 

    if (sendOTP($recipientEmail, $otp)) {
        header("Location: verify_otp.php");
        exit();
    } else {
        $_SESSION['otp_error'] = "Failed to send OTP. Please try again.";
        header("Location: index3.php");
        exit();
    }
} else {
    $_SESSION['otp_error'] = "Invalid request.";
    header("Location: index3.php");
    exit();
}
?>
