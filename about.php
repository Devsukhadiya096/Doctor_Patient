<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rural Healthcare System</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="index.css">
    <style>
        /* Custom CSS for styling */
        .hero-section {
            background-image: url('assets/doc.jpg'); /* Replace with a healthcare-related image */
            background-size: cover;
            background-position: center;
            color: white;
            padding: 200px 0;
            text-align: center;
        }
        .section-heading {
            font-size: 36px;
            font-weight: 600;
            margin-top: 20px;
        }
        .section-subheading {
            font-size: 18px;
            color: #555;
            margin-bottom: 30px;
        }
    </style>
</head>
<body>
    <!----Navigation Bar------->
    <header>
        <div class="container header-container">
            <h1>Health<span>Care</span></h1>
            <nav>
                <ul>
                    <li><a href="index.php">Home</a></li>
                    <li><a href="services.php">Services</a></li>
                    <li><a href="about.php">About Us</a></li>
                    <li><a href="contact.php">Contact Us</a></li>
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
    
    <!-- Hero Section -->
    <section class="hero-section">
        <div class="container">
            <h1>Welcome to Rural Healthcare System</h1>
            <p>Providing Quality Health Services to the Heart of Our Rural Communities</p>
            <a href="#" class="btn btn-light btn-lg">Learn More</a>
        </div>
    </section>

    <!-- About Section -->
    <section class="container my-5">
        <div class="row">
            <div class="col-lg-6">
                <h2 class="section-heading">About Us</h2>
                <p class="section-subheading">We are dedicated to offering affordable and accessible healthcare services to the rural population, ensuring every community receives quality care and support.</p>
                <p>Our healthcare system focuses on preventative care, chronic disease management, and essential medical services tailored for rural settings. We work closely with local communities to enhance health outcomes and quality of life.</p>
            </div>
            <div class="col-lg-6">
                <img src="assets/doctorss.jpg" class="img-fluid" alt="Healthcare Image"> <!-- Replace with appropriate image -->
            </div>
        </div>
    </section>

    <!-- Mission and Vision Section -->
    <section class="bg-light py-5">
        <div class="container">
            <div class="row text-center">
                <div class="col-md-6">
                    <h3 class="section-heading">Our Mission</h3>
                    <p class="section-subheading">To provide equitable healthcare services that enhance the quality of life for rural communities.</p>
                </div>
                <div class="col-md-6">
                    <h3 class="section-heading">Our Vision</h3>
                    <p class="section-subheading">To be the leading provider of innovative healthcare solutions in rural areas, empowering communities to thrive.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Services Section -->
    <section class="container my-5">
        <div class="row">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Primary Care</h5>
                        <p class="card-text">Providing essential primary healthcare services for families and individuals.</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Chronic Disease Management</h5>
                        <p class="card-text">Managing long-term conditions such as diabetes, hypertension, and more.</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Community Outreach</h5>
                        <p class="card-text">Engaging communities through health education and awareness programs.</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="bg-primary text-white text-center py-4">
        <div class="container">
            <p>&copy; 2024 Rural Healthcare System. All Rights Reserved.</p>
        </div>
    </footer>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
