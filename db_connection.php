<?php
$servername = "localhost";
$username = "root"; // Your DB username
$password = ""; // Your DB password
$database = "healthcare"; // Your DB name

$conn = mysqli_connect($servername, $username, $password, $database);

if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
?>
    