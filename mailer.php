<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
require 'vendor/autoload.php';

function sendOTP($recipientEmail, $otp, $role = null) {
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'abhinavsaireddykasu.com';
        $mail->Password   = 'qaiv sopm azoz ijeg';
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;
        $mail->setFrom('abhinavsaireddykasu.com', 'My PHP App');
        $mail->addAddress($recipientEmail);
        $mail->isHTML(true);
        
        // Customize email based on role
        if ($role === 'Admin') {
            $mail->Subject = 'Admin Password Reset OTP';
            $mail->Body    = "Your Admin Password Reset OTP is: <b>$otp</b> (valid for 10 minutes)";
        } else {
            $mail->Subject = 'Password Reset OTP';
            $mail->Body    = "Your Password Reset OTP is: <b>$otp</b> (valid for 10 minutes)";
        }
        
        $mail->AltBody = "Your OTP is: $otp";
        $mail->send();
        return true;
    } catch (Exception $e) {
        return false;
    }
}
?>
