<?php
include 'db_connection.php';

header('Content-Type: application/json');  // Ensure it returns JSON

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $userID = $_POST["userID"];
    $fullName = $_POST["fullName"];
    $email = $_POST["email"];
    $phoneNumber = $_POST["phoneNumber"];
    $address = $_POST["address"];
    $role = $_POST["role"];

    $sql = "UPDATE users SET fullName = ?, email = ?, phoneNumber = ?, address = ?, role = ? WHERE userID = ?";
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ssssss", $fullName, $email, $phoneNumber, $address, $role, $userID);

    if ($stmt->execute()) {
        echo json_encode(["success" => true, "message" => "User updated successfully!"]);
    } else {
        echo json_encode(["success" => false, "message" => "Error updating user."]);
    }

    $stmt->close();
    $conn->close();
}
?>
