<?php
include 'db_connection.php';

if (isset($_GET['userID'])) {
    $userID = $_GET['userID'];
    $sql = "SELECT userID, fullName, email, phoneNumber, address, role FROM users WHERE userID = ?";
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $userID);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($row = $result->fetch_assoc()) {
        echo json_encode(["success" => true, "userID" => $row['userID'], "fullName" => $row['fullName'], "email" => $row['email'], "phoneNumber" => $row['phoneNumber'], "address" => $row['address'], "role" => $row['role']]);
    } else {
        echo json_encode(["success" => false]);
    }

    $stmt->close();
    $conn->close();
}
?>
