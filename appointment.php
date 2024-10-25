
<?php
session_start(); // Start the session

$host = "localhost";
$user = "root"; // Your database username
$pass = ""; // Your database password
$db = "healthcare"; // Your database name

$conn = new mysqli($host, $user, $pass, $db);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Fetch random diseases from the database
$diseases = [];
$result = $conn->query("SELECT id, name FROM diseases ORDER BY RAND() LIMIT 5"); // Get 5 random diseases
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $diseases[] = $row;
    }
}

// Handle form submission for booking an appointment
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Check if "Other" is selected
    $disease_id = $_POST['disease'];
    $other_disease = $_POST['other_disease'] ?? ''; // Get other disease input
    $appointment_slot = $_POST['slot'];
    $user_id = $_SESSION['user_id']; // Get user ID from session

    // If "Other" is selected, save the disease name instead of the ID
    if ($disease_id === 'other' && !empty($other_disease)) {
        // Optionally, you can insert this "other" disease into the database
        $stmt = $conn->prepare("INSERT INTO diseases (name) VALUES (?)");
        $stmt->bind_param("s", $other_disease);
        $stmt->execute();
        $disease_id = $conn->insert_id; // Get the newly inserted disease ID
        $stmt->close();
    }

    $stmt = $conn->prepare("INSERT INTO appointments (user_id, disease_id, slot) VALUES (?, ?, ?)");
    $stmt->bind_param("iis", $user_id, $disease_id, $appointment_slot);

    if ($stmt->execute()) {
        // Redirect to the homepage after successful booking
        header("Location: index.php"); // Change 'home.php' to the actual homepage file
        exit(); // Ensure no further code is executed
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
    <link rel="stylesheet" href="style.css">
    <title>Book Appointment</title>
    <script>
        function toggleOtherDiseaseInput() {
            const diseaseSelect = document.getElementById('disease');
            const otherDiseaseInput = document.getElementById('otherDiseaseContainer');
            if (diseaseSelect.value === 'other') {
                otherDiseaseInput.style.display = 'block';
            } else {
                otherDiseaseInput.style.display = 'none';
            }
        }
    </script>
</head>
<body>
    <div class="form-container">
        <h2>Book an Appointment</h2>
        <form action="appointment.php" method="POST">
            <label for="disease">Select Disease:</label>
            <select name="disease" id="disease" onchange="toggleOtherDiseaseInput()" required>
                <option value="">Select a disease</option>
                <?php foreach ($diseases as $disease): ?>
                    <option value="<?php echo $disease['id']; ?>"><?php echo htmlspecialchars($disease['name']); ?></option>
                <?php endforeach; ?>
                <option value="other">Other</option>
            </select>

            <div id="otherDiseaseContainer" style="display: none;">
                <label for="other_disease">Please specify:</label>
                <input type="text" name="other_disease" id="other_disease" placeholder="Describe your symptoms">
            </div>

            <label for="slot">Select Appointment Slot:</label>
            <select name="slot" id="slot" required>
                <option value="">Select a time slot</option>
                <option value="09:00 AM">09:00 AM</option>
                <option value="10:00 AM">10:00 AM</option>
                <option value="11:00 AM">11:00 AM</option>
                <option value="01:00 PM">01:00 PM</option>
                <option value="02:00 PM">02:00 PM</option>
                <option value="03:00 PM">03:00 PM</option>
            </select>

            <button type="submit">Book Appointment</button>
        </form>
    </div>
</body>
</html>
