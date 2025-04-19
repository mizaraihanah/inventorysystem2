<?php
session_start();

// Redirect to login page if user is not logged in
if (!isset($_SESSION['userID'])) {
    header("Location: login.html");
    exit();
}

// Include database connection
include 'db_connection.php';

// Fetch user fullName for the welcome message
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

// Fetch all users from the database
$sql_users = "SELECT userID, fullName, username, email, phoneNumber, address, role FROM users";
$result_users = $conn->query($sql_users);

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - User Management</title>
    <link rel="stylesheet" href="admin_dashboard.css">
    <link rel="stylesheet" href="sidebar.css">
    <link rel="stylesheet" href="admin_usermanagement.css">
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
                <a href="admin_usermanagement.php" class="nav-item active">
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
                <a href="profile.php" class="nav-item">
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
            <h1>User Management</h1>
        </div>

        <!-- Add User Button -->
        <div class="user-actions">
            <button id="addUserBtn">Add User</button>
        </div>

        <!-- User Modal Popup -->
    <div id="userModal" class="modal">
    <div class="modal-content">
        <span class="close close-add">&times;</span>
        <h2>Add User</h2>
        <form id="userForm">
                    <label for="userID">User ID:</label>
                    <input type="text" id="userID" name="userID" required>

                    <label for="userUsername">Username:</label>
                    <input type="text" id="userUsername" name="userUsername" required>

                    <label for="userName">Full Name:</label>
                    <input type="text" id="userName" name="userName" required>

                    <label for="userEmail">Email:</label>
                    <input type="email" id="userEmail" name="userEmail" required>

                    <label for="userPhone">Phone Number:</label>
                    <input type="text" id="userPhone" name="userPhone" required>

                    <label for="userAddress">Address:</label>
                    <textarea id="userAddress" name="userAddress" required></textarea>

                    <label for="userPassword">Password:</label>
                    <input type="password" id="userPassword" name="userPassword" required>

                    <label for="userRole">Role:</label>
                    <select id="userRole" name="userRole" required>
                        <option value="Administrator">Administrator</option>
                        <option value="Inventory Manager">Inventory Manager</option>
                        <option value="Bakery Staff">Bakery Staff</option>
                    </select>

                    <button type="submit">Add User</button>
                </form>
            </div>
        </div>

        <!-- Update User Modal -->
    <div id="updateUserModal" class="modal">
    <div class="modal-content">
        <span class="close close-update">&times;</span>
        <h2>Update User</h2>
        <form id="updateUserForm" method="POST" action="admin_updateuser.php">

                    <input type="hidden" id="updateUserID" name="userID">

                    <label for="updateFullName">Full Name:</label>
                    <input type="text" id="updateFullName" name="fullName" required>

                    <label for="updateEmail">Email:</label>
                    <input type="email" id="updateEmail" name="email" required>

                    <label for="updatePhoneNumber">Phone Number:</label>
                    <input type="text" id="updatePhoneNumber" name="phoneNumber" required>

                    <label for="updateAddress">Address:</label>
                    <input type="text" id="updateAddress" name="address" required>

                    <label for="updateRole">Role:</label>
                    <select id="updateRole" name="role" required>
                        <option value="Administrator">Administrator</option>
                        <option value="Inventory Manager">Inventory Manager</option>
                        <option value="Bakery Staff">Bakery Staff</option>
                    </select>

                    <button type="submit">Update User</button>
                </form>
            </div>
        </div>
<!-- User List -->
<div class="user-container" id="userCardsContainer">
    <?php while ($row = $result_users->fetch_assoc()) { ?>
        <div class="user-card">
            <div class="user-info">
                <h3><?php echo htmlspecialchars($row['fullName']); ?></h3>
                <p><strong>Username:</strong> <?php echo htmlspecialchars($row['username']); ?></p>
                <p><strong>Email:</strong> <?php echo htmlspecialchars($row['email']); ?></p>
                <p><strong>Phone:</strong> <?php echo htmlspecialchars($row['phoneNumber']); ?></p>
                <p><strong>Address:</strong> <?php echo htmlspecialchars($row['address']); ?></p>
                <p><strong>Role:</strong> <?php echo htmlspecialchars($row['role']); ?></p>
            </div>
            <div class="user-actions">
                <button class="edit-btn" data-id="<?php echo $row['userID']; ?>" title="Edit User">
                    <i class="fas fa-edit"></i> Edit
                </button>
                <button class="delete-btn" data-id="<?php echo $row['userID']; ?>" title="Delete User">
                    <i class="fas fa-trash"></i> Delete
                </button>
                    </div>
                </div>
            <?php } ?>
        </div>
    </div>

    <script src="admin_usermanagement.js"></script>

</body>
</html>
