<?php
session_start(); // Start the session
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HealthCare Homepage</title>
    <link rel="stylesheet" href="index.css"> <!-- Link to the CSS file -->
</head>
<body>

<header>
    <div class="container header-container">
        <h1>Health<span>Care</span></h1>
        <nav>
    <ul>
        <li><a href="#">Home</a></li>
        <li><a href="services.php">Services</a></li>
        <li><a href="about.php">About Us</a></li>
        <li><a href="contact.php">Contact Us</a></li>
        <?php if (isset($_SESSION['username'])): ?>
            <li>
                <a href="user_profile.php">Hello, <?php echo htmlspecialchars($_SESSION['username']); ?>!</a>
            </li>
            <li><a href="logout.php">Logout</a></li> <!-- Logout link -->
        <?php else: ?>
            <li><a href="login.php">Login</a></li>
        <?php endif; ?>
    </ul>
</nav>

    </div>
</header>

<!-- Banner Section -->
<section class="banner">
    <div class="container">
        <img src="assets/banner.png" alt="HealthCare Banner" class="banner-image">
        <h2>Welcome to Our HealthCare Services</h2>
        <p>Your health is our utmost priority. We are here to provide you with the best care.</p>
        <a href="#" class="btn">Get Started</a>
    </div>
</section>

<section class="services">
    <div class="container">
        <h2>Our Services</h2>
        <div class="service-list">
            <div class="service-item">
                <img src="assets/consult.gif" alt="Consultation" class="service-image">
                <i class="fas fa-stethoscope"></i>
                <h3>Consultation</h3>
                <p>Get expert consultations from qualified healthcare professionals.</p>
            </div>
            <div class="service-item">
                <img src="assets/hospital.gif" alt="Emergency Care" class="service-image">
                <i class="fas fa-ambulance"></i>
                <h3>Emergency Care</h3>
                <p>24/7 emergency care services for critical health conditions.</p>
            </div>
            <div class="service-item">
                <img src="assets/dai.gif" alt="Diagnostics" class="service-image">
                <i class="fas fa-vials"></i>
                <h3>Diagnostics</h3>
                <p>State-of-the-art diagnostic facilities for accurate and timely results.</p>
            </div>
        </div>
    </div>
</section>

<section class="appointments">
    <div class="container">
        <h2>Book an Appointment</h2>
        <p>Select a disease and choose an appointment slot.</p>
        <?php if (isset($_SESSION['user_id'])): ?>
            <!-- If user is logged in, show the button to book appointment -->
            <a href="appointment.php" class="btn btn-appointment">Schedule Appointment</a>
        <?php else: ?>
            <!-- If user is not logged in, show a message to log in first -->
            <p>Please <a href="login.php" style="color:#007bff; text-decoration: underline;">login</a> to book an appointment.</p>
        <?php endif; ?>
    </div>
</section>

<footer>
    <div class="container">
        <p>&copy; 2024 HealthCare. All Rights Reserved.</p>
    </div>
</footer>

</body>

<!-- <script>
    document.addEventListener('DOMContentLoaded', function() {
        const navToggle = document.createElement('button');
        navToggle.innerText = 'Menu';
        navToggle.style.color = 'white'; 
        navToggle.style.backgroundColor = 'transparent';
        navToggle.style.border = 'none';
        navToggle.style.cursor = 'pointer';
        navToggle.addEventListener('click', () => {
            const navList = document.querySelector('nav ul');
            navList.classList.toggle('active'); // Toggle 'active' class
        });

        const header = document.querySelector('header .container');
        header.insertBefore(navToggle, header.children[1]); // Insert button before the nav
    });
</script> -->

</html>
