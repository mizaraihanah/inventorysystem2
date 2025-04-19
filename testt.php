<?php
// SMTP Test Script

// Require PHPMailer
require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

function testSMTP() {
    $mail = new PHPMailer(true);

    try {
        // Enable verbose debug output
        $mail->SMTPDebug = 2; // Detailed debug information
        
        // Logging configuration
        $logFile = 'smtp_debug.log';
        $mail->Debugoutput = function($str, $level) use ($logFile) {
            file_put_contents($logFile, date('Y-m-d H:i:s') . ": $str\n", FILE_APPEND);
        };

        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'rotiseribakeryemail@gmail.com';
        $mail->Password   = 'jlxf jvxl ezhn txum'; // Your App Password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;

        // Set email parameters
        $mail->setFrom('rotiseribakeryemail@gmail.com', 'SMTP Test');
        $mail->addAddress('rotiseribakeryemail@gmail.com'); // Send to yourself
        $mail->Subject = 'SMTP Connection Test';
        $mail->Body    = 'This is a test email to verify SMTP connection.';

        // Send email
        if($mail->send()) {
            echo "SMTP Test Successful! Email sent.\n";
            return true;
        } else {
            echo "SMTP Test Failed. Check the debug log.\n";
            return false;
        }
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        return false;
    }
}

// Run the test
testSMTP();
?>