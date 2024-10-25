<?php
session_start();
if (!isset($_SESSION['admin_id'])) {
    header('Location: admin_login.php');
    exit();
}

require_once 'db_connection.php';

// Fetch appointments details
$sql = "SELECT appointments.id, users.username, diseases.name AS disease_name, appointments.slot, appointments.status 
        FROM appointments 
        JOIN users ON appointments.user_id = users.id 
        JOIN diseases ON appointments.disease_id = diseases.id";

$stmt = $conn->prepare($sql);

// Check if preparation was successful
if (!$stmt) {
    die("Failed to prepare statement: " . $conn->error);
}

// Execute the statement
$stmt->execute();
$appointments = $stmt->get_result();

// Check if the query returned any results
if (!$appointments) {
    die("Error fetching appointments: " . $stmt->error);
}

// Approve or deny an appointment
// Approve or deny an appointment
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $appointmentId = $_POST['appointment_id'];
    $action = $_POST['action'];
    $adminId = $_SESSION['admin_id']; // Get the current admin's ID

    $newStatus = ($action === 'approve') ? 'approved' : 'denied';

    // Update the appointment status and set the admin_id
    $updateSql = "UPDATE appointments SET status = ?, admin_id = ? WHERE id = ?";
    $updateStmt = $conn->prepare($updateSql);
    $updateStmt->bind_param("sii", $newStatus, $adminId, $appointmentId); // Correctly bind all three parameters
    $updateStmt->execute();
    
    header('Location: admin_dashboard.php'); // Redirect after update
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Appointments</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>Admin Dashboard</h1>
        <h2>Appointments List</h2>
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Disease</th>
                    <th>Slot</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($row = $appointments->fetch_assoc()): ?>
                    <tr>
                        <td><?php echo $row['id']; ?></td>
                        <td><?php echo htmlspecialchars($row['username']); ?></td>
                        <td><?php echo htmlspecialchars($row['disease_name']); ?></td>
                        <td><?php echo htmlspecialchars($row['slot']); ?></td>
                        <td><?php echo htmlspecialchars($row['status']); ?></td>
                        <td>
                            <?php if ($row['status'] === 'pending'): ?>
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="appointment_id" value="<?php echo $row['id']; ?>">
                                    <button type="submit" name="action" value="approve" class="btn btn-success btn-sm">Approve</button>
                                    <button type="submit" name="action" value="deny" class="btn btn-danger btn-sm">Deny</button>
                                </form>
                            <?php else: ?>
                                <span class="badge badge-<?php echo $row['status'] === 'approved' ? 'success' : 'danger'; ?>">
                                    <?php echo ucfirst($row['status']); ?>
                                </span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
