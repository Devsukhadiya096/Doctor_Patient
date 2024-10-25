<?php
session_start();
// Include database connection
require 'db_connection.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php"); // Redirect to login if not logged in
    exit();
}

$user_id = $_SESSION['user_id'];

// Fetch user details
$stmt = $conn->prepare("SELECT username FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

// Fetch appointments for the user
// Fetch appointments for the user, including admin name
$appointments_stmt = $conn->prepare("SELECT a.id, a.slot, a.disease_id, a.status, ad.username AS admin_name 
                                      FROM appointments a 
                                      LEFT JOIN admin ad ON a.admin_id = ad.id 
                                      WHERE a.user_id = ?");
$appointments_stmt->bind_param("i", $user_id);
$appointments_stmt->execute();
$appointments_result = $appointments_stmt->get_result();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Profile</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="index.css">
</head>
<body>
    <!-- Navbar -->
    <header>
        <div class="container header-container">
            <h1>Health<span>Care</span></h1>
            <nav>
                <ul>
                    <li><a href="index.php">Home</a></li>
                    <li><a href="#">Services</a></li>
                    <li><a href="about.php">About Us</a></li>
                    <li><a href="contact.php">Contact Us</a></li>
                    <?php if (isset($_SESSION['username'])): ?>
                        <li><a href="#">Hello, <?php echo htmlspecialchars($_SESSION['username']); ?>!</a></li>
                        <!-- <li><a href="logout.php">Logout</a></li> Logout link -->
                    <?php else: ?>
                        <li><a href="login.php">Login</a></li>
                    <?php endif; ?>
                </ul>
            </nav>
        </div>
    </header>

    <div class="container mt-5">
        <h2>User Profile</h2>
        <h4>Welcome, <?php echo htmlspecialchars($user['username']); ?></h4>
        
        <h5>Your Appointments:</h5>
        <table class="table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Slot</th>
                    <th>Disease ID</th>
                    <th>Status</th>
                    <th>Approved By</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($appointment = $appointments_result->fetch_assoc()): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($appointment['id']); ?></td>
                        <td><?php echo htmlspecialchars($appointment['slot']); ?></td>
                        <td><?php echo htmlspecialchars($appointment['disease_id']); ?></td>
                        <td><?php echo htmlspecialchars($appointment['status']); ?></td>
                        <td><?php echo htmlspecialchars($appointment['admin_name'] ? $appointment['admin_name'] : 'Pending'); ?></td> <!-- Show admin name or 'Pending' -->

                    </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>

    <!-- Bootstrap JS and jQuery -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
