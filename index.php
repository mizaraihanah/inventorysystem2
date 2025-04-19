<?php
session_start();

// Redirect logged-in users to their dashboard
if (isset($_SESSION['userID'])) {
    switch ($_SESSION['role']) {
        case 'Bakery Staff':  // Match the database role names
            header("Location: dashboard/php/dashboard.php");
            exit();
        case 'Inventory Manager':
            header("Location: imanager_dashboard.php");
            exit();
        case 'Administrator':
            header("Location: admin_dashboard.php");
            exit();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="loginpage/css/loginstyle.css">
    <style>
        .forgot-password {
            text-align: right;
            margin-top: -10px;
            margin-bottom: 10px;
        }
        
        .forgot-password a {
            font-size: 0.9rem;
            color: #0561FC;
            text-decoration: none;
        }
        
        .forgot-password a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-box">
            <h1>Roti Seri Bakery Inventory <br> Management System</h1>
            <h2>Log in</h2>
            <form id="loginForm" action="login.php" method="POST">
                <div class="form-group">
                    <label for="userID">User ID<span>*</span></label>
                    <input type="text" id="userID" name="userID" required>
                </div>
                <div class="form-group">
                    <label for="password">Password<span>*</span></label>
                    <div class="password-wrapper">
                        <input type="password" id="password" name="password" required>
                        <i class="fas fa-eye" id="togglePassword"></i>
                    </div>
                </div>
                <div class="forgot-password">
                    <a href="forgot_password.php">Forgot Password?</a>
                </div>
                <div class="form-group">
                    <label for="role">Role<span>*</span></label>
                    <select id="role" name="role" required>
                        <option value="">Select Role</option>
                        <option value="Bakery Staff">Bakery Staff</option>
                        <option value="Inventory Manager">Inventory Manager</option>
                        <option value="Administrator">Administrator</option>
                    </select>
                </div>
                <div class="form-group remember-me">
                    <input type="checkbox" id="remember" name="remember">
                    <label for="remember">Remember me</label>
                </div>
                <button type="submit" class="btn">Sign in</button>
            </form>
        </div>
    </div>

    <script src="loginpage/js/loginscript.js"></script>
</body>
</html>