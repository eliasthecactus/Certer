<?php
// auth.php - Authentication Logic

require_once 'config.php'; // Access global constants

/**
 * Checks if the user is currently authenticated and if the session has not expired.
 * Updates the last activity timestamp if active.
 *
 * @return bool True if authenticated, false otherwise.
 */
function is_user_authenticated(): bool
{
    if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] < AUTH_TIMEOUT_SECONDS)) {
            $_SESSION['last_activity'] = time(); // Update last activity time
            return true;
        } else {
            // Session expired, clear session data
            session_unset();
            session_destroy();
            session_start(); // Start a new session for the login attempt
            return false;
        }
    }
    return false;
}

/**
 * Handles login and logout POST requests.
 * Sets session variables for authentication or clears them on logout.
 * Redirects on successful login/logout.
 *
 * @param string|null &$login_error Reference to a variable to store login error messages.
 * @return void
 */
function handle_auth_actions(?string &$login_error): void
{
    if (isset($_POST['login'])) {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';

        if ($username === AUTH_USERNAME && $password === AUTH_PASSWORD) {
            $_SESSION['logged_in'] = true;
            $_SESSION['last_activity'] = time();
            // Redirect to clear POST data and prevent re-submission
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit();
        } else {
            $login_error = "Invalid username or password.";
        }
    }

    if (isset($_POST['logout'])) {
        session_unset();
        session_destroy();
        session_start(); // Start a new session for the login page
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit();
    }
}
