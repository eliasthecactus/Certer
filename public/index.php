<?php
// index.php - Main Application Entry Point

// Start the session to persist authentication state and form progress/results
session_start();

// Include all necessary modular files
require_once 'config.php';
require_once 'auth.php';
require_once 'openssl_functions.php';
require_once 'form_handler.php';
require_once 'template_parts.php';

// --- Authentication Logic ---
$login_error = null;
handle_auth_actions($login_error);
$is_authenticated = is_user_authenticated();

// --- Form Data and Step Management ---
// Initialize form_data with empty values.
$form_data = [
    'cn' => '',
    'org' => '',
    'ou' => '',
    'city' => '',
    'state' => '',
    'country' => '',
    'dns' => '',
    'ips' => '',
];

// Load default values from config.php. These will pre-fill the form initially.
foreach ($default_form_values as $key => $value) {
    // Only apply defaults if the key exists in $form_data to prevent adding unexpected fields
    if (array_key_exists($key, $form_data)) {
        $form_data[$key] = $value;
    }
}

// Variables to hold generation results (persisted in session)
$submitted_data = $_SESSION['submitted_data'] ?? null;
$generated_files = $_SESSION['generated_files'] ?? [];
$generated_file_paths = $_SESSION['generated_file_paths'] ?? [];
$openssl_output = $_SESSION['openssl_output'] ?? [];
$generation_status = $_SESSION['generation_status'] ?? '';
$generation_log = $_SESSION['generation_log'] ?? '';
$key_decision_cn = ''; // As step 1.5 is gone, this can effectively be an empty string
$generate_new_key_flag = $_SESSION['generate_new_key_flag'] ?? true;

// NEW: Variables to hold CA request results
$ca_certificate = $_SESSION['ca_certificate'] ?? '';
$ca_verification_output = $_SESSION['ca_verification_output'] ?? '';
$ca_request_status = $_SESSION['ca_request_status'] ?? '';
$ca_request_log = $_SESSION['ca_request_log'] ?? ''; // Initialize to empty string


// Determine current step.
$current_step = (int)($_SESSION['current_step'] ?? 1); // Ensure int type

// --- Handle Session State on GET Requests (after redirects) ---
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // If 'just_generated' flag is set, it means we redirected after a successful CSR generation.
    // We want to remain on step 3 to show results. Clear the flag.
    if (isset($_SESSION['just_generated'])) {
        unset($_SESSION['just_generated']);
        // current_step should already be 3 from form_handler redirect
    }
    // If not just generated (i.e., a fresh visit, or after logout/done),
    // and we're *not* explicitly on step 2 (which means we came from step 1 via 'next_step')
    // then reset everything for a fresh start at step 1.
    else if ($current_step !== 2 && !isset($_SESSION['form_data_temp'])) {
        // Clear all form-related session data
        unset($_SESSION['submitted_data']);
        unset($_SESSION['generated_files']);
        unset($_SESSION['generated_file_paths']);
        unset($_SESSION['openssl_output']);
        unset($_SESSION['generation_status']);
        unset($_SESSION['generation_log']);
        unset($_SESSION['key_decision_cn']);
        unset($_SESSION['generate_new_key_flag']);
        unset($_SESSION['form_data_temp']);
        unset($_SESSION['ca_certificate']); // Clear CA results
        unset($_SESSION['ca_verification_output']);
        unset($_SESSION['ca_request_status']);
        unset($_SESSION['ca_request_log']); // Clear CA log from session


        // Reset local variables
        $submitted_data = null;
        $generated_files = [];
        $generated_file_paths = [];
        $openssl_output = [];
        $generation_status = '';
        $generation_log = '';
        $key_decision_cn = '';
        $generate_new_key_flag = true;
        $ca_certificate = ''; // Reset CA results
        $ca_verification_output = '';
        $ca_request_status = '';
        $ca_request_log = ''; // Reset local variable


        // Ensure step is 1
        $current_step = 1;
        $_SESSION['current_step'] = 1;
    }
}

// If form data was stored in session temporarily (e.g., when moving from step 1 to step 2),
// merge it into the current $form_data, overriding defaults if present.
// This merge happens *after* the initial $form_data is populated with config.php defaults,
// ensuring that hostname-specific data from session takes precedence.
if (isset($_SESSION['form_data_temp'])) {
    $form_data = array_merge($form_data, $_SESSION['form_data_temp']);
}


if ($is_authenticated) {
    // Handle form submissions if authenticated.
    // This function will update $form_data, $current_step, and the session variables for results.
    handle_form_submission(
        $form_data,
        $current_step,
        $submitted_data,
        $generated_files,
        $generated_file_paths,
        $openssl_output,
        $generation_status,
        $generation_log,
        $key_decision_cn,
        $generate_new_key_flag,
        // Pass CA variables by reference for updating
        $ca_certificate,
        $ca_verification_output,
        $ca_request_status,
        $ca_request_log // No longer needs (string) cast as it's initialized
    );
}

// Debug: Log the CA request log content just before rendering
// error_log("Debug: CA Request Log content before rendering: " . $ca_request_log); // Removed this as per user request
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Certificate Generator</title>
    <link rel="stylesheet" href="/assets/tailwind.min.css" />
</head>
<body class="bg-gray-100 text-gray-800 font-sans antialiased">
    <?php render_header($is_authenticated); ?>

    <main class="container mx-auto px-4 mt-10 max-w-2xl">
        <?php if (!$is_authenticated): ?>
            <?php render_login_form($login_error); ?>
        <?php else: ?>
            <?php
            // The value of $current_step here determines what is rendered.
            render_generator_form(
                $form_data,
                $current_step,
                $submitted_data,
                $generated_files,
                $generated_file_paths,
                $openssl_output,
                $generation_status,
                $generation_log,
                $key_decision_cn,
                $generate_new_key_flag,
                // Pass CA variables to render function (ca_request_log removed from here)
                $ca_certificate,
                $ca_verification_output,
                $ca_request_status
            );
            ?>
        <?php endif; ?>
    </main>

    <?php render_footer(); ?>
</body>
</html>
