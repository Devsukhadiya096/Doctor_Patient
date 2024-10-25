<?php
session_start();

$host = "localhost";
$user = "root";
$pass = "";
$db = "healthcare";

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $email = $_POST['email'];
    $message = $_POST['message'];

    $stmt = $conn->prepare("INSERT INTO contact_messages (email, message) VALUES (?, ?)");
    $stmt->bind_param("ss", $email, $message);

    if ($stmt->execute()) {
        echo "Thank you! Your message has been received.";
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
}

$conn->close();
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Us - HealthCare</title>
    <link rel="stylesheet" href="contact.css"> <!-- Link to your CSS file -->
</head>
<body>

<header>
    <div class="container header-container">
        <h1>Health<span>Care</span></h1>
        <nav>
            <ul>
                <li><a href="index.php">Home</a></li>
                <li><a href="services.php">Services</a></li>
                <li><a href="about.php">About Us</a></li>
                <?php if (isset($_SESSION['username'])): ?>
                    <li><a href="#">Hello, <?php echo htmlspecialchars($_SESSION['username']); ?>!</a></li>
                    <li><a href="logout.php">Logout</a></li> <!-- Logout link -->
                <?php else: ?>
                    <li><a href="login.php">Login</a></li>
                <?php endif; ?>
            </ul>
        </nav>
    </div>
</header>

<section class="contact">
    <div class="container">
        <h2>Contact Us</h2>
        <p>If you have any questions or need assistance, feel free to contact us using the form below:</p>
        <form action="contact.php" method="POST">
            <div class="form-group">
                <label for="name">Name:</label>
                <input type="text" id="name" name="name" required>
            </div>
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="message">Message:</label>
                <textarea id="message" name="message" rows="5" required></textarea>
            </div>
            <button type="submit">Submit</button>
        </form>
    </div>
</section>

<footer>
    <div class="container">
        <p>&copy; 2024 HealthCare. All Rights Reserved.</p>
    </div>
</footer>

</body>
</html>
