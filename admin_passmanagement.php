<?php
session_start();

// Redirect to login page if user is not logged in or not an admin
if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Administrator') {
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

// Fetch all password reset requests (we'll create this table later)
$sql_requests = "SELECT r.*, u.fullName, u.email 
                FROM password_reset_requests r 
                JOIN users u ON r.userID = u.userID 
                WHERE r.status = 'pending' 
                ORDER BY r.request_date DESC";
$result_requests = $conn->query($sql_requests);

// Fetch all users for password management
$sql_users = "SELECT userID, fullName, username, email, role FROM users";
$result_users = $conn->query($sql_users);

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - Password Management</title>
    <link rel="stylesheet" href="admin_dashboard.css">
    <link rel="stylesheet" href="sidebar.css">
    <link rel="stylesheet" href="admin_passmanagement.css">
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
                <a href="admin_logsdisplay.php" class="nav-item">
                    <i class="fas fa-file-alt"></i>
                    <div class="nav-text">Logs</div>
                </a>
                <a href="admin_passmanagement.php" class="nav-item active">
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
            <h1>Password Management</h1>
        </div>

        <!-- Password Reset Requests Section -->
        <div class="section">
            <h2><i class="fas fa-bell"></i> Password Reset Requests</h2>
            <div class="requests-container">
                <?php if ($result_requests && $result_requests->num_rows > 0) : ?>
                    <table class="requests-table">
                        <thead>
                            <tr>
                                <th>User ID</th>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Request Date</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while ($request = $result_requests->fetch_assoc()) : ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($request['userID']); ?></td>
                                    <td><?php echo htmlspecialchars($request['fullName']); ?></td>
                                    <td><?php echo htmlspecialchars($request['email']); ?></td>
                                    <td><?php echo htmlspecialchars($request['request_date']); ?></td>
                                    <td>
                                        <button class="reset-btn" data-id="<?php echo $request['userID']; ?>" 
                                                data-email="<?php echo $request['email']; ?>"
                                                data-request="<?php echo $request['request_id']; ?>">
                                            <i class="fas fa-key"></i> Reset Password
                                        </button>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                <?php else : ?>
                    <div class="no-requests">
                        <i class="fas fa-check-circle"></i>
                        <p>No pending password reset requests.</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- User Password Management Section -->
        <div class="section">
            <h2><i class="fas fa-users-cog"></i> User Password Management</h2>
            
            <!-- Search bar -->
            <div class="search-container">
                <input type="text" id="userSearch" placeholder="Search for users...">
                <i class="fas fa-search search-icon"></i>
            </div>
            
            <div class="users-container">
                <table class="users-table">
                    <thead>
                        <tr>
                            <th>User ID</th>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($user = $result_users->fetch_assoc()) : ?>
                            <tr>
                                <td><?php echo htmlspecialchars($user['userID']); ?></td>
                                <td><?php echo htmlspecialchars($user['fullName']); ?></td>
                                <td><?php echo htmlspecialchars($user['email']); ?></td>
                                <td><?php echo htmlspecialchars($user['role']); ?></td>
                                <td>
                                    <button class="change-pwd-btn" data-id="<?php echo $user['userID']; ?>" 
                                            data-email="<?php echo $user['email']; ?>">
                                        <i class="fas fa-key"></i> Change Password
                                    </button>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Reset Password Modal -->
    <div id="resetPasswordModal" class="modal">
        <div class="modal-content">
            <span class="close">&times;</span>
            <h2>Reset Password</h2>
            <form id="resetPasswordForm">
                <input type="hidden" id="resetUserID" name="userID">
                <input type="hidden" id="resetEmail" name="email">
                <input type="hidden" id="requestID" name="requestID">
                
                <div class="form-group">
                    <label for="newPassword">New Password:</label>
                    <div class="password-field">
                        <input type="password" id="newPassword" name="newPassword" required minlength="8">
                        <i class="fas fa-eye toggle-password"></i>
                    </div>
                    <div class="password-strength">
                        <div class="strength-meter"></div>
                        <div class="strength-text">Password strength: <span>Weak</span></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="confirmPassword">Confirm Password:</label>
                    <div class="password-field">
                        <input type="password" id="confirmPassword" name="confirmPassword" required minlength="8">
                        <i class="fas fa-eye toggle-password"></i>
                    </div>
                    <div class="password-match"></div>
                </div>
                
                <div class="form-group">
                    <div class="checkbox-container">
                        <input type="checkbox" id="sendEmail" name="sendEmail" checked>
                        <label for="sendEmail">Send new password to user's email</label>
                    </div>
                </div>
                
                <div class="form-actions">
                    <button type="submit" id="submitResetBtn">Reset Password</button>
                    <button type="button" id="cancelResetBtn">Cancel</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Change Password Modal -->
    <div id="changePasswordModal" class="modal">
        <div class="modal-content">
            <span class="close">&times;</span>
            <h2>Change User Password</h2>
            <form id="changePasswordForm">
                <input type="hidden" id="changeUserID" name="userID">
                <input type="hidden" id="changeEmail" name="email">
                
                <div class="form-group">
                    <label for="adminPassword">Your Admin Password:</label>
                    <div class="password-field">
                        <input type="password" id="adminPassword" name="adminPassword" required>
                        <i class="fas fa-eye toggle-password"></i>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="userNewPassword">New User Password:</label>
                    <div class="password-field">
                        <input type="password" id="userNewPassword" name="userNewPassword" required minlength="8">
                        <i class="fas fa-eye toggle-password"></i>
                    </div>
                    <div class="password-strength">
                        <div class="strength-meter"></div>
                        <div class="strength-text">Password strength: <span>Weak</span></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="userConfirmPassword">Confirm New Password:</label>
                    <div class="password-field">
                        <input type="password" id="userConfirmPassword" name="userConfirmPassword" required minlength="8">
                        <i class="fas fa-eye toggle-password"></i>
                    </div>
                    <div class="password-match"></div>
                </div>
                
                <div class="form-group">
                    <div class="checkbox-container">
                        <input type="checkbox" id="notifyUser" name="notifyUser" checked>
                        <label for="notifyUser">Notify user via email</label>
                    </div>
                </div>
                
                <div class="form-actions">
                    <button type="submit" id="submitChangeBtn">Change Password</button>
                    <button type="button" id="cancelChangeBtn">Cancel</button>
                </div>
            </form>
        </div>
    </div>

    <script src="admin_passmanagement.js"></script>
</body>
</html>