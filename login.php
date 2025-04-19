<?php
session_start();
require_once 'db_connection.php'; // Ensure this file exists and has a valid `$conn`

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $userID = trim($_POST["userID"]);
    $password = trim($_POST["password"]);
    $role = trim($_POST["role"]);

    if (empty($userID) || empty($password) || empty($role)) {
        echo "<script>alert('All fields are required!'); window.location='index.php';</script>";
        exit();
    }

    $query = "SELECT userID, username, password, role FROM users WHERE userID=? AND role=?";
    $stmt = $conn->prepare($query);

    // ✅ Debug SQL Preparation
    if (!$stmt) {
        die("DEBUG: Query Preparation Failed - " . $conn->error); // Print SQL error
    }

    $stmt->bind_param("ss", $userID, $role);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows == 1) {
        $user = $result->fetch_assoc();

        // ✅ Debug Password Hash
        echo "DEBUG: Stored Hash: " . $user['password'] . "<br>";
        echo "DEBUG: Entered Password: " . $password . "<br>";

        if (password_verify($password, $user['password'])) {
            $_SESSION['userID'] = $user['userID'];
            $_SESSION['username'] = $user['username']; // Store username too
            $_SESSION['role'] = $user['role'];

            // ✅ Debug Redirect
            echo "DEBUG: Login Success! Redirecting...<br>";

            // Redirect based on role
            switch ($role) {
                case "Bakery Staff":
                    header("Location: dashboard/php/dashboard.php");
                    break;
                case "Inventory Manager":
                    header("Location: imanager_dashboard.php");
                    break;
                case "Administrator":
                    header("Location: admin_dashboard.php");
                    break;
                default:
                    header("Location: index.php");
                    break;
            }
            exit();
        } else {
            echo "<script>alert('Incorrect password!'); window.location='index.php';</script>";
        }
    } else {
        echo "<script>alert('Invalid credentials!'); window.location='index.php';</script>";
    }
}
?>
