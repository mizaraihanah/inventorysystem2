<?php
$servername = "localhost"; // Change if using another host
$username = "root"; // Change if using another MySQL user
$password = ""; // Set your MySQL password here
$database = "roti_seri_bakery_inventory"; // Ensure database exists

$conn = new mysqli($servername, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
