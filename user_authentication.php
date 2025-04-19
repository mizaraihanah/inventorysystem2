<?php
session_start();
include 'db_connection.php'; // Ensure this file contains DB connection setup

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $userID = trim($_POST['userID']);
    $password = trim($_POST['password']);
    $role = trim($_POST['role']);

    if (empty($userID) || empty($password) || empty($role)) {
        echo "<script>alert('All fields are required!'); window.location.href='../index.php';</script>";
        exit();
    }

    $stmt = $conn->prepare("SELECT username, password, role FROM users WHERE userID = ? AND role = ?");
    $stmt->bind_param("ss", $userID, $role);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows == 1) {
        $row = $result->fetch_assoc();
        if (password_verify($password, $row['password'])) {
            $_SESSION['userID'] = $userID;
            $_SESSION['username'] = $row['username'];
            $_SESSION['role'] = $row['role'];
            
            // Redirect based on role
            if ($row['role'] == 'admin') {
                header("Location: ../admin_dashboard.php");
            } elseif ($row['role'] == 'manager') {
                header("Location: ../manager_dashboard.php");
            } else {
                header("Location: ../staff_dashboard.php");
            }
            exit();
        } else {
            echo "<script>alert('Invalid credentials!'); window.location.href='../index.php';</script>";
        }
    } else {
        echo "<script>alert('Invalid credentials!'); window.location.href='../index.php';</script>";
    }

    $stmt->close();
    $conn->close();
}
?>
