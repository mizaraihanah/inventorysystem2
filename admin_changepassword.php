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
    $adminPassword = trim($_POST['adminPassword']);
    $userID = trim($_POST['userID']);
    $email = trim($_POST['email']);
    $newPassword = trim($_POST['userNewPassword']);
    $confirmPassword = trim($_POST['userConfirmPassword']);
    $notifyUser = isset($_POST['notifyUser']) ? true : false;
    
    // Validate data
    if (empty($adminPassword) || empty($userID) || empty($newPassword) || empty($confirmPassword)) {
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
        
        // Verify admin password
        $adminVerifySQL = "SELECT password FROM users WHERE userID = ?";
        $stmt = $conn->prepare($adminVerifySQL);
        $stmt->bind_param("s", $adminID);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows !== 1) {
            throw new Exception("Admin account not found");
        }
        
        $row = $result->fetch_assoc();
        $storedHash = $row['password'];
        
        if (!password_verify($adminPassword, $storedHash)) {
            throw new Exception("Admin password is incorrect");
        }
        
        // Hash the new password for user
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        
        // Update user password
        $updatePasswordSQL = "UPDATE users SET password = ? WHERE userID = ?";
        $stmt = $conn->prepare($updatePasswordSQL);
        $stmt->bind_param("ss", $hashedPassword, $userID);
        
        if (!$stmt->execute()) {
            throw new Exception("Failed to update password: " . $stmt->error);
        }
        
        // Check how many rows were affected
        if ($stmt->affected_rows == 0) {
            throw new Exception("Password update had no effect. Check if the user exists.");
        }
        
        // Log the password change action
        $logSQL = "INSERT INTO admin_logs (admin_id, action, affected_user, action_details, ip_address) 
                  VALUES (?, 'password_change', ?, 'Changed user password', ?)";
        $stmt = $conn->prepare($logSQL);
        $ipAddress = $_SERVER['REMOTE_ADDR'];
        $stmt->bind_param("sss", $adminID, $userID, $ipAddress);
        
        if (!$stmt->execute()) {
            throw new Exception("Failed to log action");
        }
        
        // Send email notification if requested
        $emailSent = false;
        if ($notifyUser && !empty($email)) {
            $emailSent = sendPasswordChangeNotification($email, $userID, $newPassword);
            
            if (!$emailSent) {
                // Log email failure
                $logEmailFailSQL = "INSERT INTO admin_logs (admin_id, action, affected_user, action_details, ip_address) 
                                   VALUES (?, 'email_fail', ?, 'Failed to send password change notification', ?)";
                $stmt = $conn->prepare($logEmailFailSQL);
                $stmt->bind_param("sss", $adminID, $userID, $ipAddress);
                $stmt->execute();
            }
        }
        
        // Commit transaction
        $conn->commit();
        
        $message = 'Password has been changed successfully';
        if ($notifyUser && !$emailSent) {
            $message .= ' but notification email could not be sent';
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
 * Sends password change notification email to user
 * 
 * @param string $email User's email address
 * @param string $userID User's ID
 * @param string $password New password
 * @return bool True if email sent successfully, false otherwise
 */
function sendPasswordChangeNotification($email, $userID, $password) {
    try {
        // Create a new PHPMailer instance
        $mail = new PHPMailer(true);
        
        // Server settings - reduced debug level
        $mail->SMTPDebug = 0; // Set to 2 for detailed debugging
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'rotiseribakeryemail@gmail.com';
        $mail->Password   = 'jlxf jvxl ezhn txum'; // Your App Password
        $mail->SMTPSecure = 'tls'; // Use string instead of PHPMailer constant
        $mail->Port       = 587;

        // Recipients
        $mail->setFrom('rotiseribakeryemail@gmail.com', 'Roti Seri Bakery Admin');
        $mail->addAddress($email);
        $mail->addReplyTo('noreply@rotiseribakery.com', 'No Reply');

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Your Password Has Been Changed - Roti Seri Bakery';
        
        $htmlMessage = "
        <html>
        <body>
            <h2>Password Change Notification</h2>
            <p>Dear User,</p>
            <p>Your password for the RotiSeri Bakery system has been reset by an administrator.</p>
            <p><strong>User ID:</strong> {$userID}</p>
            <p><strong>New Password:</strong> {$password}</p>
            <p>Please change your password upon first login.</p>
            <p>If you did not request this change, contact the administrator immediately.</p>
        </body>
        </html>";
        
        $textMessage = "Your password for User ID {$userID} has been changed by an administrator. Your new password is: {$password}. Please log in and change your password.";
        
        $mail->Body = $htmlMessage;
        $mail->AltBody = $textMessage;

        // Send email and return result directly
        return $mail->send();
        
    } catch (Exception $e) {
        // Log any exceptions
        error_log("Email Exception in Password Change: " . $e->getMessage());
        return false;
    }
}
?>
