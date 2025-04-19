
<?php
require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

function testEmailSend() {
    try {
        // Create a new PHPMailer instance
        $mail = new PHPMailer(true);

        // Enable verbose debug output
        $mail->SMTPDebug = 2; // Detailed debug information
        
        // Logging configuration
        $logFile = 'detailed_email_debug.log';
        $mail->Debugoutput = function($str, $level) use ($logFile) {
            file_put_contents($logFile, date('Y-m-d H:i:s') . ": $str\n", FILE_APPEND);
        };

        // SMTP configuration
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'rotiseribakeryemail@gmail.com';
        $mail->Password   = 'jlxf jvxl ezhn txum'; // Your App Password
        $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;

        // Sender and recipient
        $mail->setFrom('rotiseribakeryemail@gmail.com', 'Roti Seri Bakery Test');
        $mail->addAddress('rotiseribakeryemail@gmail.com'); // Send to yourself

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Email Test ' . date('Y-m-d H:i:s');
        $mail->Body    = 'This is a test email to verify SMTP connection. Timestamp: ' . date('Y-m-d H:i:s');

        // Send the email
        $result = $mail->send();
        
        // Log the result
        error_log("Email Test Result: " . ($result ? "Success" : "Failure"));
        
        return $result;
    } catch (Exception $e) {
        // Log any exceptions
        error_log("Email Exception: " . $e->getMessage());
        file_put_contents('detailed_email_debug.log', "Full Exception: " . $e->getMessage() . "\n", FILE_APPEND);
        
        return false;
    }
}

// Run the test
$testResult = testEmailSend();
echo $testResult ? "Email sent successfully!" : "Email sending failed.";
?>
