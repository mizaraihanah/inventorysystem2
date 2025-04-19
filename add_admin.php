<?php
require_once 'db_connection.php'; // Ensure this file connects to your database

// New Admin User Details
$userID = "adminTest";
$fullName = "Admin Test"; // Adding fullName field
$username = "adminTest";  // Keeping username same as userID
$email = "admin@test.com";
$phoneNumber = "0123456789";
$address = "Test Address";
$role = "Administrator";
$password_plain = "admin123"; // Change this to a secure password

// Hash the password before storing it
$password_hashed = password_hash($password_plain, PASSWORD_DEFAULT);

// Insert Query
$query = "INSERT INTO users (userID, fullName, username, email, phoneNumber, address, password, role, created_at) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())";

$stmt = $conn->prepare($query);
$stmt->bind_param("ssssssss", $userID, $fullName, $username, $email, $phoneNumber, $address, $password_hashed, $role);

if ($stmt->execute()) {
    echo "✅ New Administrator user added successfully!<br>";
    echo "🔑 Use this to log in: <br>";
    echo "User ID: $userID<br>";
    echo "Password: $password_plain (hashed in database)";
} else {
    echo "❌ Error: " . $stmt->error;
}

$stmt->close();
$conn->close();
?>
