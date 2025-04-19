<?php
include 'db_connection.php';

header('Content-Type: application/json');

if (isset($_GET['userID'])) {
    $userID = $_GET['userID'];

    $sql = "SELECT userID, fullName, email, phoneNumber, address, role FROM users WHERE userID = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $userID);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($row = $result->fetch_assoc()) {
        echo json_encode($row);
    } else {
        echo json_encode(["error" => "User not found"]);
    }

    $stmt->close();
    $conn->close();
} else {
    echo json_encode(["error" => "No userID provided"]);
}
?>