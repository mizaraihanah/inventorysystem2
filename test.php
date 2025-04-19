<?php
require_once 'db_connection.php';

$userID = "adminTest";
$role = "Administrator";
$entered_password = "admin123"; // Password you entered during login

$query = "SELECT password FROM users WHERE userID = ? AND role = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("ss", $userID, $role);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows == 1) {
    $user = $result->fetch_assoc();
    $stored_hashed_password = $user['password'];

    if (password_verify($entered_password, $stored_hashed_password)) {
        echo "✅ Password is correct!";
    } else {
        echo "❌ Password is incorrect!";
    }
} else {
    echo "❌ No matching user found!";
}

$stmt->close();
$conn->close();
?>
