<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Our Services - Rural Healthcare System</title>
    <link rel="stylesheet" href="index.css">
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        /* Custom Styles */
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
        }

        .hero-section {
            background: url('assets/nguy-n-hi-p-2rNHliX6XHk-unsplash.jpg') no-repeat center center;
            background-size: cover;
            height: 60vh;
            position: relative;
            color: white;
            display: flex;
            align-items: center;
        justify-content: center;
        }

        .hero-section h1 {
            font-size: 3.5rem;
            font-weight: bold;
        }

        .hero-section p {
            font-size: 1.2rem;
            margin-top: 10px;
        }

        .services-section {
            padding: 70px 0;
            background-color: #f4f4f4;
        }

        .services-section h2 {
            text-align: center;
            font-weight: bold;
            margin-bottom: 50px;
        }

        .service-card {
            padding: 20px;
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }

        .service-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 25px rgba(0, 0, 0, 0.2);
        }

        .service-card img {
            height: 180px;
            width: 100%;
            object-fit: cover;
            border-radius: 8px;
        }

        .service-card h3 {
            margin-top: 20px;
            font-size: 1.5rem;
            font-weight: 600;
        }

        .service-card p {
            margin-top: 10px;
            color: #777;
        }

        .service-card .btn {
            margin-top: 15px;
            border-radius: 20px;
            background-color: #007bff;
            color: #fff;
        }

        .service-card .btn:hover {
            background-color: #0056b3;
        }

        @media (max-width: 768px) {
            .hero-section h1 {
                font-size: 2.5rem;
            }
            .service-card img {
                height: 150px;
            }
        }
        .collapse.navbar-collapse {
            float: left;
            margin-left: 59%;
}
    </style>
</head>
<body>
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
        <div class="container text-center">
            <h1>Our Services</h1>
            <p>Comprehensive Healthcare Solutions for Rural Communities</p>
        </div>
    </section>

    <!-- Services Section -->
    <section class="services-section">
        <div class="container">
            <h2>What We Offer</h2>
            <div class="row">
                <!-- Service 1 -->
                <div class="col-md-4 mb-4">
                    <div class="service-card text-center shadow-sm">
                        <img src="assets/por.avif" alt="Primary Care" class="img-fluid">
                        <h3>Primary Care</h3>
                        <p>Providing essential health services, routine checkups, and preventive care to support healthy living in rural communities.</p>
                        <button class="btn btn-primary">Learn More</button>
                    </div>
                </div>

                <!-- Service 2 -->
                <div class="col-md-4 mb-4">
                    <div class="service-card text-center shadow-sm">
                        <img src="assets/ambu.avif" alt="Emergency Services" class="img-fluid">
                        <h3>Emergency Services</h3>
                        <p>Rapid response teams available 24/7 to handle critical situations and ensure timely treatment for all emergency cases.</p>
                        <button class="btn btn-primary">Learn More</button>
                    </div>
                </div>

                <!-- Service 3 -->
                <div class="col-md-4 mb-4">
                    <div class="service-card text-center shadow-sm">
                        <img src="assets/mom.avif" alt="Maternal Health" class="img-fluid">
                        <h3>Maternal Health</h3>
                        <p>Dedicated support for pregnant women, including prenatal care, safe deliveries, and postnatal assistance for mothers.</p>
                        <button class="btn btn-primary">Learn More</button>
                    </div>
                </div>
            </div>
            
            <div class="row">
                <!-- Service 4 -->
                <div class="col-md-4 mb-4">
                    <div class="service-card text-center shadow-sm">
                        <img src="assets/pediatric.avif" alt="Pediatric Care" class="img-fluid">
                        <h3>Pediatric Care</h3>
                        <p>Specialized care for children to promote healthy growth, timely vaccinations, and treatment of childhood illnesses.</p>
                        <button class="btn btn-primary">Learn More</button>
                    </div>
                </div>

                <!-- Service 5 -->
                <div class="col-md-4 mb-4">
                    <div class="service-card text-center shadow-sm">
                        <img src="assets/mob.jpg" alt="Mobile Health Clinics" class="img-fluid">
                        <h3>Mobile Health Clinics</h3>
                        <p>Bringing healthcare services directly to remote areas through fully equipped mobile units staffed by professionals.</p>
                        <button class="btn btn-primary">Learn More</button>
                    </div>
                </div>

                <!-- Service 6 -->
                <div class="col-md-4 mb-4">
                    <div class="service-card text-center shadow-sm">
                        <img src="assets/tele.jpg" alt="Telemedicine Services" class="img-fluid">
                        <h3>Telemedicine Services</h3>
                        <p>Offering remote consultations and telehealth services to connect patients with specialists and provide time.</p>
                        <button class="btn btn-primary">Learn More</button>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Bootstrap JS and dependencies -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
