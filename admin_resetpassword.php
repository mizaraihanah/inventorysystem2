<?php
session_start();
require_once 'db_connection.php';
require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

header('Content-Type: application/json');

// Check if user is logged in and has admin privileges
if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Administrator') {
    echo json_encode(['success' => false, 'message' => 'Unauthorized access']);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get form data
    $adminID = $_SESSION['userID'];
    $userID = trim($_POST['userID']);
    $email = trim($_POST['email']);
    $newPassword = trim($_POST['newPassword']);
    $confirmPassword = trim($_POST['confirmPassword']);
    $requestID = isset($_POST['requestID']) ? trim($_POST['requestID']) : null;
    $sendEmail = isset($_POST['sendEmail']) ? true : false;
    
    // Validate data
    if (empty($userID) || empty($newPassword) || empty($confirmPassword)) {
        echo json_encode(['success' => false, 'message' => 'All fields are required']);
        exit();
    }
    
    if ($newPassword !== $confirmPassword) {
        echo json_encode(['success' => false, 'message' => 'Passwords do not match']);
        exit();
    }
    
    if (strlen($newPassword) < 8) {
        echo json_encode(['success' => false, 'message' => 'Password must be at least 8 characters long']);
        exit();
    }
    
    try {
        // Start transaction
        $conn->begin_transaction();
        
        // Hash the new password
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        
        // Update user password
        $updatePasswordSQL = "UPDATE users SET password = ? WHERE userID = ?";
        $stmt = $conn->prepare($updatePasswordSQL);
        $stmt->bind_param("ss", $hashedPassword, $userID);
        
        if (!$stmt->execute()) {
            throw new Exception("Failed to update password: " . $stmt->error);
        }
        
        // Check if update was successful
        if ($stmt->affected_rows == 0) {
            throw new Exception("Password update had no effect. Check if the user exists.");
        }
        
        // Update request status if request ID is provided
        if (!empty($requestID)) {
            $updateRequestSQL = "UPDATE password_reset_requests 
                                SET status = 'completed', 
                                    completed_date = NOW(), 
                                    completed_by = ? 
                                WHERE request_id = ? AND userID = ?";
            $stmt = $conn->prepare($updateRequestSQL);
            $stmt->bind_param("sis", $adminID, $requestID, $userID);
            
            if (!$stmt->execute()) {
                throw new Exception("Failed to update request status: " . $stmt->error);
            }
        }
        
        // Log the password reset action
        $logSQL = "INSERT INTO admin_logs (admin_id, action, affected_user, action_details, ip_address) 
                  VALUES (?, 'password_reset', ?, 'Reset user password', ?)";
        $stmt = $conn->prepare($logSQL);
        $ipAddress = $_SERVER['REMOTE_ADDR'];
        $stmt->bind_param("sss", $adminID, $userID, $ipAddress);
        
        if (!$stmt->execute()) {
            throw new Exception("Failed to log action: " . $stmt->error);
        }
        
        // Send email notification if requested
        $emailSent = false;
        if ($sendEmail && !empty($email)) {
            $emailSent = sendPasswordResetEmail($email, $userID, $newPassword);
            
            if (!$emailSent) {
                // Log email failure
                $logEmailFailSQL = "INSERT INTO admin_logs (admin_id, action, affected_user, action_details, ip_address) 
                                   VALUES (?, 'email_fail', ?, 'Failed to send password reset email', ?)";
                $stmt = $conn->prepare($logEmailFailSQL);
                $stmt->bind_param("sss", $adminID, $userID, $ipAddress);
                $stmt->execute();
            }
        }
        
        // Commit transaction
        $conn->commit();
        
        $message = 'Password has been reset successfully';
        if ($sendEmail && !$emailSent) {
            $message .= ', but notification email could not be sent';
        }
        
        echo json_encode(['success' => true, 'message' => $message]);
    } catch (Exception $e) {
        // Rollback transaction on error
        $conn->rollback();
        echo json_encode(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
    } finally {
        $conn->close();
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid request method']);
}

/**
 * Sends password reset notification email to user
 * 
 * @param string $email User's email address
 * @param string $userID User's ID
 * @param string $password New password
 * @return bool True if email sent successfully, false otherwise
 */
function sendPasswordResetEmail($email, $userID, $password) {
    try {
        // Create a new PHPMailer instance
        $mail = new PHPMailer(true);
        
        // Server settings - reduced debug level for production
        $mail->SMTPDebug = 0; // Set to 2 for detailed debugging
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'rotiseribakeryemail@gmail.com';
        $mail->Password   = 'jlxf jvxl ezhn txum'; // Your App Password
        $mail->SMTPSecure = 'tls';
        $mail->Port       = 587;

        // Recipients
        $mail->setFrom('rotiseribakeryemail@gmail.com', 'Roti Seri Bakery Admin');
        $mail->addAddress($email);
        $mail->addReplyTo('noreply@rotiseribakery.com', 'No Reply');

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Your Password Has Been Reset - Roti Seri Bakery';
        
        $htmlMessage = "
        <html>
        <body>
            <h2>Password Reset Notification</h2>
            <p>Dear User,</p>
            <p>Your password for the Roti Seri Bakery system has been reset by an administrator.</p>
            <p><strong>User ID:</strong> {$userID}</p>
            <p><strong>New Password:</strong> {$password}</p>
            <p>For security reasons, please change your password upon first login.</p>
            <p>If you did not request this password reset, please contact your administrator immediately.</p>
            <p><br>Regards,<br>Roti Seri Bakery Team</p>
        </body>
        </html>";
        
        $textMessage = "Your password for User ID {$userID} has been reset. Your new password is: {$password}. For security reasons, please change your password upon first login.";
        
        $mail->Body = $htmlMessage;
        $mail->AltBody = $textMessage;

        // Send email
        return $mail->send();
    } catch (Exception $e) {
        // Log any exceptions
        error_log("Email Exception in Password Reset: " . $e->getMessage());
        return false;
    }
}
?>
