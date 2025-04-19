<?php
include 'db_connection.php';

header('Content-Type: application/json');

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Sanitize and validate inputs
    $userID = trim($_POST['userID']);
    $username = trim($_POST['userUsername']);
    $fullName = trim($_POST['userName']);
    $email = trim($_POST['userEmail']);
    $phoneNumber = trim($_POST['userPhone']);
    $address = trim($_POST['userAddress']);
    $password = $_POST['userPassword'];
    $role = trim($_POST['userRole']);

    // Input validation
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $userID)) {
        echo json_encode(["success" => false, "message" => "Invalid user ID!"]);
        exit();
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(["success" => false, "message" => "Invalid email format!"]);
        exit();
    }

    // Update: Flexible phone number validation (allows spaces, dashes, parentheses)
    if (!preg_match('/^[\d\s\-\(\)]{10,15}$/', $phoneNumber)) {
        echo json_encode(["success" => false, "message" => "Invalid phone number!"]);
        exit();
    }

    if (strlen($password) < 8) {
        echo json_encode(["success" => false, "message" => "Password must be at least 8 characters!"]);
        exit();
    }

    // Hash password
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    // Insert into database
    $sql = "INSERT INTO users (userID, username, fullName, email, phoneNumber, address, password, role) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ssssssss", $userID, $username, $fullName, $email, $phoneNumber, $address, $hashedPassword, $role);

    if ($stmt->execute()) {
        echo json_encode(["success" => true, "message" => "User added successfully!"]);
    } else {
        echo json_encode(["success" => false, "message" => "Error: " . $stmt->error]);
    }

    $stmt->close();
    $conn->close();
}
?>
