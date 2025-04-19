<?php
include 'db_connection.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $action = $_POST['action'];

    if ($action == "add") {
        $name = $_POST['userName'];
        $username = $_POST['userUsername'];
        $password = password_hash($_POST['userPassword'], PASSWORD_DEFAULT);
        $role = $_POST['userRole'];

        $sql = "INSERT INTO users (fullName, username, password, role) VALUES (?, ?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ssss", $name, $username, $password, $role);
        if ($stmt->execute()) {
            echo "User added successfully!";
        } else {
            echo "Error adding user.";
        }
        $stmt->close();
    }

    if ($action == "delete") {
        $userID = $_POST['userID'];
        $sql = "DELETE FROM users WHERE userID = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $userID);
        if ($stmt->execute()) {
            echo "User deleted successfully!";
        } else {
            echo "Error deleting user.";
        }
        $stmt->close();
    }

    if ($action == "update") {
        $userID = $_POST['userID'];
        $newRole = $_POST['newRole'];

        $sql = "UPDATE users SET role = ? WHERE userID = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("si", $newRole, $userID);
        if ($stmt->execute()) {
            echo "User role updated successfully!";
        } else {
            echo "Error updating role.";
        }
        $stmt->close();
    }
}

$conn->close();
?>
