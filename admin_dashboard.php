<?php
session_start();

// Redirect to login page if user is not logged in
if (!isset($_SESSION['userID'])) {
    header("Location: login.html");
    exit();
}

// Include database connection
include 'db_connection.php';

// Fetch user fullName
$userID = $_SESSION['userID'];
$sql = "SELECT fullName FROM users WHERE userID = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("s", $userID);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    $fullName = $row['fullName'];
} else {
    $fullName = "Admin"; 
}

$stmt->close();

// Fetch total users
$sql_users = "SELECT COUNT(*) AS totalUsers FROM users";
$result_users = $conn->query($sql_users);
$row_users = $result_users->fetch_assoc();
$totalUsers = $row_users['totalUsers'];

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Administrator Dashboard</title>
    <link rel="stylesheet" href="admin_dashboard.css">
    <link rel="stylesheet" href="sidebar.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

</head>

<body>
    <div class="sidebar-container">
        <div class="header-section">
            <div class="company-logo">
                <img src="image/icon/logo.png" class="logo-icon" alt="Company Logo">
                <div class="company-text">
                    <span class="company-name">RotiSeri</span>
                    <span class="company-name2">Admin</span>
                </div>
            </div>

            <nav class="nav-container" role="navigation">
                <a href="admin_dashboard.php" class="nav-item">
                    <i class="fas fa-home"></i>
                    <div class="nav-text">Home</div>
                </a>
                <a href="admin_usermanagement.php" class="nav-item">
                    <i class="fa fa-user nav-icon"></i>
                    <div class="nav-text">User Management</div>
                </a>
                <a href="admin_logsdisplay.php" class="nav-item">
                    <i class="fas fa-file-alt"></i>
                    <div class="nav-text">Logs</div>
                </a>
                <a href="admin_passmanagement.php" class="nav-item">
                    <i class="fas fa-key"></i>
                    <div class="nav-text">Password Management</div>
                </a>
                <a href="profile.php" class="nav-item">
                    <i class="fas fa-user-circle"></i>
                    <div class="nav-text">My Profile</div>
                </a>
                <a href="logout.php" class="nav-item">
                    <i class="fas fa-sign-out-alt nav-icon"></i>
                    <div class="nav-text">Log Out</div>
                </a>
            </nav>
        </div>

        <div class="footer-section"></div>
    </div>

<!-- Main Content -->
<div class="main-content">
        <div class="dashboard-header">
            <h1>Welcome, <?php echo htmlspecialchars($fullName); ?>!</h1>
        </div>

        <div class="dashboard-container">
            <div class="dashboard-card">
                <i class="fas fa-users fa-2x"></i>
                <h3>Total Users</h3>
                <p id="totalUsers"><?php echo $totalUsers; ?></p>
            </div>
            <div class="dashboard-card">
                <i class="fas fa-file-alt fa-2x"></i>
                <h3>Total Logs</h3>
                <p id="totalLogs">0</p>
            </div>
        </div>

        <div class="dashboard-charts">
            <h3>Activity Overview</h3>
            <canvas id="activityChart" width="100%" height="50"></canvas>
        </div>
    </div>

    <script src="admin_dashboard.js"></script>
</body>

</html>
