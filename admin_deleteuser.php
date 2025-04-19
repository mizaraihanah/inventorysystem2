<?php
include 'db_connection.php';

header('Content-Type: application/json');

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $userID = trim($_POST['userID']);

    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $userID)) {
        echo json_encode(["success" => false, "message" => "Invalid user ID"]);
        exit();
    }

    $sql = "DELETE FROM users WHERE userID = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $userID);

    if ($stmt->execute()) {
        echo json_encode(["success" => true, "message" => "User deleted successfully"]);
    } else {
        echo json_encode(["success" => false, "message" => "Error deleting user"]);
    }

    $stmt->close();
    $conn->close();
}
?>
