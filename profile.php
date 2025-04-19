<?php
session_start();

// Redirect to login page if user is not logged in
if (!isset($_SESSION['userID'])) {
    header("Location: login.html");
    exit();
}

// Include database connection
include 'db_connection.php';

// Fetch user details
$userID = $_SESSION['userID'];
$sql = "SELECT fullName, email, userID, role, phoneNumber, address FROM users WHERE userID = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("s", $userID);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    $fullName = $row['fullName'];
    $email = $row['email'];
    $userID = $row['userID'];
    $role = $row['role'];
    $phoneNumber = $row['phoneNumber'];
    $address = $row['address'];
} else {
    // Redirect if no user is found
    header("Location: login.html");
    exit();
}

$stmt->close();
$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile</title>
    <link rel="stylesheet" href="admin_dashboard.css">
    <link rel="stylesheet" href="sidebar.css">
    <link rel="stylesheet" href="profile.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
</head>
<body>

<!-- Sidebar -->
<div class="sidebar-container">
    <div class="header-section">
        <div class="company-logo">
            <img src="image/icon/logo.png" class="logo-icon" alt="Company Logo">
            <div class="company-text">
                <span class="company-name">RotiSeri</span>
                <span class="company-name2">Admin</span>
            </div>
        </div>

        <nav class="nav-container">
            <a href="admin_dashboard.php" class="nav-item">
                <i class="fas fa-home"></i>
                <div class="nav-text">Home</div>
            </a>
            <a href="admin_usermanagement.php" class="nav-item">
                <i class="fa fa-user"></i>
                <div class="nav-text">User Management</div>
            </a>
            <a href="logs.php" class="nav-item">
                <i class="fas fa-file-alt"></i>
                <div class="nav-text">Logs</div>
            </a>
            <a href="admin_passmanagement.php" class="nav-item">
                <i class="fas fa-key"></i>
                <div class="nav-text">Password Management</div>
            </a>
            <a href="profile.php" class="nav-item active">
                <i class="fas fa-user-circle"></i>
                <div class="nav-text">My Profile</div>
            </a>
            <a href="logout.php" class="nav-item">
                <i class="fas fa-sign-out-alt"></i>
                <div class="nav-text">Log Out</div>
            </a>
        </nav>
    </div>
</div>

<!-- Main Content -->
<div class="main-content">
    <div class="dashboard-header">
        <h1>My Profile</h1>
    </div>

    <div class="profile-container">
        <table class="profile-table">
            <tr>
                <td><strong>Full Name</strong></td>
                <td><?php echo htmlspecialchars($fullName); ?></td>
            </tr>
            <tr>
                <td><strong>Email</strong></td>
                <td><?php echo htmlspecialchars($email); ?></td>
            </tr>
            <tr>
                <td><strong>User ID</strong></td>
                <td><?php echo htmlspecialchars($userID); ?></td>
            </tr>
            <tr>
                <td><strong>Role</strong></td>
                <td><?php echo htmlspecialchars($role); ?></td>
            </tr>
            <tr>
                <td><strong>Phone Number</strong></td>
                <td><?php echo htmlspecialchars($phoneNumber); ?></td>
            </tr>
            <tr>
                <td><strong>Address</strong></td>
                <td><?php echo htmlspecialchars($address); ?></td>
            </tr>
        </table>
    </div>
</div>

</body>
</html>
