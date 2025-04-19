<?php
require_once 'db_connection.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userID = trim($_POST['userID']);
    $email = trim($_POST['email']);
    
    // Validate inputs
    if (empty($userID) || empty($email)) {
        echo "<script>alert('Both User ID and Email are required'); window.location='forgot_password.html';</script>";
        exit();
    }
    
    // Check if user exists
    $sql = "SELECT userID, email FROM users WHERE userID = ? AND email = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $userID, $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        echo "<script>alert('No matching account found. Please check your User ID and Email.'); window.location='forgot_password.html';</script>";
        exit();
    }
    
    // User found, create password reset request
    try {
        // Check if there's already a pending request
        $checkSql = "SELECT request_id FROM password_reset_requests WHERE userID = ? AND status = 'pending'";
        $stmt = $conn->prepare($checkSql);
        $stmt->bind_param("s", $userID);
        $stmt->execute();
        $checkResult = $stmt->get_result();
        
        if ($checkResult->num_rows > 0) {
            echo "<script>alert('You already have a pending password reset request. Please wait for an administrator to process it.'); window.location='index.php';</script>";
            exit();
        }
        
        // Insert new request
        $insertSql = "INSERT INTO password_reset_requests (userID, request_date, status, ip_address) VALUES (?, NOW(), 'pending', ?)";
        $stmt = $conn->prepare($insertSql);
        $ipAddress = $_SERVER['REMOTE_ADDR'];
        $stmt->bind_param("ss", $userID, $ipAddress);
        
        if ($stmt->execute()) {
            // Send notification to admin (optional)
            notifyAdmins($userID, $email);
            
            // Send confirmation to user
            sendConfirmationEmail($email, $userID);
            
            echo "<script>alert('Your password reset request has been submitted. An administrator will process your request shortly.'); window.location='index.php';</script>";
        } else {
            throw new Exception("Failed to submit request");
        }
    } catch (Exception $e) {
        echo "<script>alert('Error: " . $e->getMessage() . "'); window.location='forgot_password.html';</script>";
    } finally {
        $conn->close();
    }
} else {
    // Display the forgot password form
    include 'forgot_password.html';
}

/**
 * Sends notification to admin users about the password reset request
 */
function notifyAdmins($userID, $userEmail) {
    global $conn;
    
    // Get all admin emails
    $sql = "SELECT email FROM users WHERE role = 'Administrator'";
    $result = $conn->query($sql);
    
    if ($result->num_rows > 0) {
        $adminEmails = [];
        while ($row = $result->fetch_assoc()) {
            $adminEmails[] = $row['email'];
        }
        
        // Send notification to each admin
        $subject = "New Password Reset Request - RotiSeri Bakery System";
        
        $message = "Dear Administrator,\n\n";
        $message .= "A password reset request has been submitted by the following user:\n";
        $message .= "User ID: " . $userID . "\n";
        $message .= "Email: " . $userEmail . "\n\n";
        $message .= "Please log in to the admin panel to process this request.\n\n";
        $message .= "Regards,\nRotiSeri Bakery System";
        
        $headers = "From: system@rotiseribakery.com\r\n";
        
        foreach ($adminEmails as $adminEmail) {
            mail($adminEmail, $subject, $message, $headers);
        }
    }
}

/**
 * Sends confirmation email to user
 */
function sendConfirmationEmail($email, $userID) {
    $subject = "Password Reset Request Confirmation - RotiSeri Bakery";
    
    $message = "Dear User,\n\n";
    $message .= "We have received your password reset request for your RotiSeri Bakery Inventory System account.\n\n";
    $message .= "Your request has been submitted to our administrators and will be processed shortly.\n";
    $message .= "You will receive another email with your new password once your request has been processed.\n\n";
    $message .= "User ID: " . $userID . "\n\n";
    $message .= "If you did not make this request, please contact our administrator immediately.\n\n";
    $message .= "Regards,\nRotiSeri Bakery Team";
    
    $headers = "From: system@rotiseribakery.com\r\n";
    $headers .= "Reply-To: noreply@rotiseribakery.com\r\n";
    
    mail($email, $subject, $message, $headers);
}
?>