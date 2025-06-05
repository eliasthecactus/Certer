<?php
// form_handler.php - Handles multi-step form submissions

require_once 'config.php';
require_once 'openssl_functions.php';

/**
 * Performs a cURL request to a Windows Certificate Authority (CA) to fetch a certificate.
 *
 * @param string $csr_content   The content of the Certificate Signing Request.
 * @param string $common_name   The Common Name (hostname) for the certificate.
 * @return array An associative array containing:
 * - 'status': 'success' or 'error'.
 * - 'certificate': The fetched certificate content (if successful).
 * - 'verification_output': Output from OpenSSL verification.
 * - 'log': Detailed log of the CA request process.
 * - 'message': Error message (if status is 'error').
 */
function perform_ca_request(string $csr_content, string $common_name): array
{
    $ca_log = '';
    $ca_status = 'error'; // Default to error
    $certificate_data = '';
    $verification_output = '';
    $error_message = '';

    $ca_log .= "Attempting to request certificate from CA for: " . $common_name . "\n";
    $ca_log .= "Starting CA request for CN: {$common_name}\n"; // Cleaned debug to log

    // --- Prepare CSR for CA Request ---
    $csr_encoded = str_replace(["\n", "\r"], '', $csr_content);
    $csr_encoded = urlencode($csr_encoded);
    $csr_encoded = str_replace('+', '%2B', $csr_encoded); // Handle literal '+' signs in the CSR for correct encoding
    $ca_log .= "CSR content encoded.\n";
    $ca_log .= "CSR encoded.\n"; // Cleaned debug to log


    // Encode certificate template name
    $cert_attrib = urlencode("CertificateTemplate:" . CA_TEMPLATE_NAME . "\r\n");
    $ca_log .= "Certificate template attribute prepared: " . CA_TEMPLATE_NAME . "\n";
    $ca_log .= "Cert template attribute prepared.\n"; // Cleaned debug to log


    // --- Request Certificate from CA (Step 1: Submission) ---
    $ca_url = "https://" . CA_FQDN . "/certsrv/certfnsh.asp";
    $ca_log .= "Submitting request to CA URL: " . $ca_url . "\n";
    $ca_log .= "Submitting request to CA URL: {$ca_url}\n"; // Cleaned debug to log

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $ca_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // DANGER: Disable SSL verification for development.
    // For production, always enable and provide CURLOPT_CAINFO pointing to your CA's root cert.
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    // curl_setopt($ch, CURLOPT_CAINFO, CA_CERT_PATH); // UNCOMMENT AND CONFIGURE FOR PRODUCTION!

    curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_NTLM); // Use NTLM authentication
    curl_setopt($ch, CURLOPT_USERPWD, CA_USERNAME . ":" . CA_PASSWORD); // Set username and password
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding: gzip, deflate',
        'Accept-Language: en-US,en;q=0.5',
        'Connection: keep-alive',
        "Host: " . CA_FQDN,
        "Referer: https://" . CA_FQDN . "/certsrv/certrqxt.asp", // Important for Windows CA
        'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'Content-Type: application/x-www-form-urlencoded',
    ]);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, "Mode=newreq&CertRequest={$csr_encoded}&CertAttrib={$cert_attrib}&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=");

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if (curl_errno($ch)) {
        $error_message = "Error requesting certificate from CA: " . curl_error($ch);
        $ca_log .= "ERROR: " . $error_message . "\n";
        $ca_log .= "CURL submission error: {$error_message}\n"; // Cleaned debug to log
        curl_close($ch);
        return ['status' => 'error', 'message' => $error_message, 'log' => $ca_log];
    }
    curl_close($ch);

    if ($http_code !== 200) {
        $error_message = "CA request failed with HTTP status {$http_code}. Response snippet: " . substr($response, 0, 500);
        $ca_log .= "ERROR: " . $error_message . "\n";
        $ca_log .= "HTTP submission error: {$http_code}. Response: {$error_message}\n"; // Cleaned debug to log
        return ['status' => 'error', 'message' => 'Failed to submit certificate request to CA.', 'ca_response_code' => $http_code, 'ca_response_body_snippet' => substr($response, 0, 500), 'log' => $ca_log];
    }
    $ca_log .= "CA submission successful (HTTP {$http_code}). Parsing response for retrieval link.\n";
    $ca_log .= "CA submission successful. HTTP: {$http_code}.\n"; // Cleaned debug to log


    // --- Parse Response for Certificate Link ---
    preg_match('/function handleGetCert\(\) {\s*location\.href\s*=\s*"([^"]+)";/s', $response, $matches);

    if (!isset($matches[1])) {
        $error_message = "Could not find certificate retrieval link in CA response. Response snippet: " . substr($response, 0, 500);
        $ca_log .= "ERROR: " . $error_message . "\n";
        $ca_log .= "Failed to parse retrieval link. Response: {$error_message}\n"; // Cleaned debug to log
        return ['status' => 'error', 'message' => 'Failed to parse CA response for certificate link.', 'log' => $ca_log];
    }
    $output_link = $matches[1];
    $cert_link = "https://" . CA_FQDN . "/certsrv/{$output_link}";
    $ca_log .= "Certificate retrieval link found: " . $cert_link . "\n";
    $ca_log .= "Cert retrieval link: {$cert_link}\n"; // Cleaned debug to log


    // --- Retrieve Certificate (Step 2: Retrieval) ---
    $ca_log .= "Attempting to retrieve certificate.\n";
    $ca_log .= "Retrieving certificate.\n"; // Cleaned debug to log
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $cert_link);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // DANGER: Disable for dev, enable for production with CURLOPT_CAINFO
    // curl_setopt($ch, CURLOPT_CAINFO, CA_CERT_PATH); // UNCOMMENT AND CONFIGURE FOR PRODUCTION!

    curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_NTLM);
    curl_setopt($ch, CURLOPT_USERPWD, CA_USERNAME . ":" . CA_PASSWORD);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding: gzip, deflate',
        'Accept-Language: en-US,en;q=0.5',
        'Connection: keep-alive',
        "Host: " . CA_FQDN,
        "Referer: https://" . CA_FQDN . "/certsrv/certrqxt.asp", // Important for CA
        'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'Content-Type: application/x-www-form-urlencoded',
    ]);

    $certificate_data = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if (curl_errno($ch)) {
        $error_message = "Error retrieving certificate: " . curl_error($ch);
        $ca_log .= "ERROR: " . $error_message . "\n";
        $ca_log .= "CURL retrieval error: {$error_message}\n"; // Cleaned debug to log
        curl_close($ch);
        return ['status' => 'error', 'message' => $error_message, 'log' => $ca_log];
    }
    curl_close($ch);

    if ($http_code !== 200) {
        $error_message = "CA retrieval failed with HTTP status {$http_code}. Response snippet: " . substr($certificate_data, 0, 500);
        $ca_log .= "ERROR: " . $error_message . "\n";
        $ca_log .= "HTTP retrieval error: {$http_code}. Response: {$error_message}\n"; // Cleaned debug to log
        return ['status' => 'error', 'message' => 'Failed to retrieve certificate from CA.', 'ca_response_code' => $http_code, 'ca_response_body_snippet' => substr($certificate_data, 0, 500), 'log' => $ca_log];
    }
    $ca_log .= "Certificate data retrieved from CA.\n";
    $ca_log .= "Certificate data retrieved successfully.\n"; // Cleaned debug to log

    // --- Save for Verification and Cleanup ---
    $temp_cert_file_path = CERT_DIR . $common_name . '.crt.tmp';
    if (file_put_contents($temp_cert_file_path, $certificate_data) === false) {
        $error_message = "Server error: Could not save certificate to '{$temp_cert_file_path}' for verification.";
        $ca_log .= "ERROR: " . $error_message . "\n";
        $ca_log .= "Error saving temp cert: {$error_message}\n"; // Cleaned debug to log
        return ['status' => 'error', 'message' => $error_message, 'log' => $ca_log];
    }
    $ca_log .= "Certificate saved temporarily for verification: " . basename($temp_cert_file_path) . "\n";
    $ca_log .= "Temp cert saved.\n"; // Cleaned debug to log


    // --- Verify Certificate ---
    $ca_log .= "Performing OpenSSL certificate verification.\n";
    $ca_log .= "Performing OpenSSL verify.\n"; // Cleaned debug to log
    $command = "openssl verify -verbose " . escapeshellarg($temp_cert_file_path) . " 2>&1";
    exec($command, $output, $return_var);
    $verification_output = implode("\n", $output);
    $ca_log .= "OpenSSL verification output:\n" . $verification_output . "\n";
    $ca_log .= "OpenSSL verify output: {$verification_output}\n"; // Cleaned debug to log


    // --- Clean up temporary certificate file ---
    unlink($temp_cert_file_path);
    $ca_log .= "Temporary certificate file removed.\n";
    $ca_log .= "Temp cert removed.\n"; // Cleaned debug to log

    if ($return_var === 0) {
        $ca_status = 'success';
        $ca_log .= "Certificate verification successful.\n";
        $ca_log .= "Cert verification successful.\n"; // Cleaned debug to log
    } else {
        $error_message = "Certificate verification failed. OpenSSL error code: {$return_var}. Output: " . $verification_output;
        $ca_log .= "ERROR: " . $error_message . "\n";
        $ca_log .= "Cert verification FAILED: {$error_message}\n"; // Cleaned debug to log
        $ca_status = 'error';
    }

    return [
        'status' => $ca_status,
        'certificate' => $certificate_data,
        'verification_output' => $verification_output,
        'log' => $ca_log,
        'message' => $error_message
    ];
}


/**
 * Handles the multi-step form submissions (Next, Back, Generate CSR, Done).
 * Updates form data and current step based on POST requests.
 * Persists generation results and key decision to session.
 *
 * @param array      &$form_data             Reference to the array holding current form field values.
 * @param int        &$current_step          Reference to the current step number.
 * @param array|null &$submitted_data         Reference to store the final submitted data for display.
 * @param array      &$generated_files       Reference to store basenames of generated files.
 * @param array      &$generated_file_paths  Reference to store web paths for generated files.
 * @param array      &$openssl_output        Reference to store raw OpenSSL command output.
 * @param string     &$generation_status      Reference to store 'success' or 'fail' status (overall status).
 * @param string     &$generation_log         Reference to store detailed generation logs (overall log).
 * @param string     &$key_decision_cn        Reference to store the CN for the key decision step (its direct use for step 1.5 is removed).
 * @param bool       &$generate_new_key_flag Reference to indicate if a new key should be generated.
 * @param string     &$ca_certificate         Reference to store the fetched certificate.
 * @param string     &$ca_verification_output Reference to store CA certificate verification output.
 *
 * @param string     &$ca_request_status      Reference to store CA request status ('success' or 'error').
 * @param string     &$ca_request_log         Reference to store CA request log.
 * @return void
 */
function handle_form_submission(
    array &$form_data,
    int &$current_step,
    ?array &$submitted_data,
    array &$generated_files,
    array &$generated_file_paths,
    array &$openssl_output,
    string &$generation_status,
    string &$generation_log,
    string &$key_decision_cn,
    bool   &$generate_new_key_flag,
    // NEW: CA request variables by reference
    string &$ca_certificate,
    string &$ca_verification_output,
    string &$ca_request_status,
    string &$ca_request_log
): void {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Clear previous generation results and key decision state if starting a new process or going back
        // This is done here to ensure it only clears when a form action is taken,
        // not on a simple page reload (GET request).
        if (isset($_POST['next_step']) || isset($_POST['prev_step']) || isset($_POST['done_and_start_over']) ||
            isset($_POST['generate_csr'])) {
            unset($_SESSION['submitted_data']);
            unset($_SESSION['generated_files']);
            unset($_SESSION['generated_file_paths']);
            unset($_SESSION['openssl_output']);
            unset($_SESSION['generation_status']);
            unset($_SESSION['generation_log']);
            unset($_SESSION['just_generated']);
            unset($_SESSION['key_decision_cn']);
            unset($_SESSION['generate_new_key_flag']);
            unset($_SESSION['form_data_temp']);
            // NEW: Clear CA related session data
            unset($_SESSION['ca_certificate']);
            unset($_SESSION['ca_verification_output']);
            unset($_SESSION['ca_request_status']);
            unset($_SESSION['ca_request_log']);


            $submitted_data = null;
            $generated_files = [];
            $generated_file_paths = [];
            $openssl_output = [];
            $generation_status = '';
            $generation_log = '';
            $key_decision_cn = '';
            $generate_new_key_flag = true;
            // NEW: Reset CA related local variables
            $ca_certificate = '';
            $ca_verification_output = '';
            $ca_request_status = '';
            $ca_request_log = '';
        }

        // Handle "Next" button from Step 1
        if (isset($_POST['next_step'])) {
            $form_data['cn'] = htmlspecialchars(trim($_POST['cn'] ?? ''));
            $_SESSION['form_data_temp'] = $form_data;

            $config_file_path = CERT_DIR . $form_data['cn'] . '.conf';
            $key_file_path = CERT_DIR . $form_data['cn'] . '.key';

            error_log("Debug: form_data before loading config in form_handler (Next click): " . print_r($form_data, true));

            if (file_exists($config_file_path)) {
                error_log("Debug: Config file found: " . $config_file_path);
                $loaded_data = json_decode(file_get_contents($config_file_path), true);
                if ($loaded_data) {
                    $form_data = array_merge($form_data, $loaded_data);
                    $form_data['cn'] = htmlspecialchars(trim($_POST['cn'] ?? ''));
                    error_log("Debug: Config data loaded and merged. New form_data in form_handler: " . print_r($form_data, true));
                } else {
                    error_log("Debug: Failed to decode JSON from config file: " . $config_file_path);
                }
            } else {
                error_log("Debug: Config file not found: " . $config_file_path);
                $form_data['dns'] = '';
                $form_data['ips'] = '';
            }

            $_SESSION['form_data_temp'] = $form_data;

            $generate_new_key_flag = !file_exists($key_file_path);
            $_SESSION['generate_new_key_flag'] = $generate_new_key_flag;

            $current_step = 2;
            $_SESSION['current_step'] = $current_step;
            session_write_close();
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit();
        }

        // Handle "Back" button from Step 2
        elseif (isset($_POST['prev_step'])) {
            $current_step = 1;
            unset($_SESSION['form_data_temp']);
            unset($_SESSION['key_decision_cn']);
            unset($_SESSION['generate_new_key_flag']);
            $_SESSION['current_step'] = $current_step;
            session_write_close();
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit();
        }
        // Handle "Generate CSR" button from Step 2
        elseif (isset($_POST['generate_csr'])) {
            // Populate $form_data with submitted values from step 2
            $form_data['cn'] = htmlspecialchars(trim($_POST['cn_display'] ?? ''));
            $form_data['org'] = htmlspecialchars(trim($_POST['org'] ?? ''));
            $form_data['ou'] = htmlspecialchars(trim($_POST['ou'] ?? ''));
            $form_data['city'] = htmlspecialchars(trim($_POST['city'] ?? ''));
            $form_data['state'] = htmlspecialchars(trim($_POST['state'] ?? ''));
            $form_data['country'] = htmlspecialchars(trim($_POST['country'] ?? ''));
            $form_data['dns'] = htmlspecialchars(trim($_POST['dns'] ?? ''));
            $form_data['ips'] = htmlspecialchars(trim($_POST['ips'] ?? ''));

            $submitted_data = $form_data;

            // --- Save Host Configuration ---
            $config_file_path = CERT_DIR . $submitted_data['cn'] . '.conf';
            file_put_contents($config_file_path, json_encode($submitted_data, JSON_PRETTY_PRINT));
            error_log("Debug: Saved config to: " . $config_file_path);

            // --- Determine Key Generation Flag for OpenSSL ---
            $key_file_path_check = CERT_DIR . $submitted_data['cn'] . '.key';
            if (isset($_POST['force_new_key']) && $_POST['force_new_key'] === 'true') {
                $generate_new_key_flag_for_openssl = true;
                error_log("Debug: User chose to force new key generation.");
            } elseif (file_exists($key_file_path_check)) {
                $generate_new_key_flag_for_openssl = false;
                error_log("Debug: Key file exists, using existing key.");
            } else {
                $generate_new_key_flag_for_openssl = true;
                error_log("Debug: No key file found, generating new key.");
            }

            // --- Call OpenSSL Generation Function (Key & CSR) ---
            $generation_results = generate_certificate_components($submitted_data, $generate_new_key_flag_for_openssl);

            $generated_files = $generation_results['generated_files'];
            $generated_file_paths = $generation_results['generated_file_paths'];
            $openssl_output = $generation_results['openssl_output'];
            $generation_status = $generation_results['generation_status'];
            $generation_log = $generation_results['generation_log'];
            $csr_content = $generation_results['csr_content']; // Get CSR content for CA request


            // --- Conditionally Request Certificate from CA ---
            if ($generation_status === 'success' && !empty($csr_content)) {
                $ca_request_data = perform_ca_request($csr_content, $submitted_data['cn']);

                $ca_certificate = $ca_request_data['certificate'] ?? '';
                $ca_verification_output = $ca_request_data['verification_output'] ?? '';
                $ca_request_status = $ca_request_data['status'];
                $ca_request_log = $ca_request_data['log'] ?? ($ca_request_data['message'] ?? 'No specific CA log available.');

                // Append CA request log to the main generation log
                $generation_log .= "\n--- CA Certificate Request Log ---\n";
                $generation_log .= $ca_request_log;


                // Override overall generation status based on CA request outcome
                if ($ca_request_status === 'error') {
                    $generation_status = 'fail'; // If CA request fails, overall status is fail
                } else {
                    // If CA request succeeded, the overall status is still 'success' from CSR gen.
                    // Now, also save the actual .crt file to certdir
                    $cert_file_path = CERT_DIR . $submitted_data['cn'] . '.crt';
                    file_put_contents($cert_file_path, $ca_certificate);
                    $generated_files[] = basename($cert_file_path);
                    $generated_file_paths[] = '/certdir/' . basename($cert_file_path);
                    $generation_log .= "Actual certificate fetched from CA and saved: " . basename($cert_file_path) . "\n";
                }
            } else {
                // If CSR generation failed, mark CA request as not attempted
                $ca_request_status = 'not_attempted';
                $ca_request_log = "CA certificate request skipped because CSR generation failed or CSR content was empty.";
                // Append this reason to the main generation log
                $generation_log .= "\n--- CA Certificate Request Log (Not Attempted) ---\n";
                $generation_log .= $ca_request_log;
            }

            $current_step = 3; // Move to Step 3 to show results
            $_SESSION['current_step'] = $current_step; // Persist step

            // Persist all generation results and current step to session
            $_SESSION['submitted_data'] = $submitted_data;
            $_SESSION['generated_files'] = $generated_files;
            $_SESSION['generated_file_paths'] = $generated_file_paths;
            $_SESSION['openssl_output'] = $openssl_output;
            $_SESSION['generation_status'] = $generation_status;
            $_SESSION['generation_log'] = $generation_log; // Save the combined log
            $_SESSION['just_generated'] = true;

            // NEW: Persist CA request results to session (for status and cert content display)
            $_SESSION['ca_certificate'] = $ca_certificate;
            $_SESSION['ca_verification_output'] = $ca_verification_output;
            $_SESSION['ca_request_status'] = $ca_request_status;
            // Removed $_SESSION['ca_request_log'] as it's now merged into generation_log

            session_write_close();
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit();
        }
        // Handle "Done" button from Step 3 (only visible on failure)
        elseif (isset($_POST['done_and_start_over'])) {
            $current_step = 1;
            unset($_SESSION['submitted_data']);
            unset($_SESSION['generated_files']);
            unset($_SESSION['generated_file_paths']);
            unset($_SESSION['openssl_output']);
            unset($_SESSION['generation_status']);
            unset($_SESSION['generation_log']);
            unset($_SESSION['just_generated']);
            unset($_SESSION['key_decision_cn']);
            unset($_SESSION['generate_new_key_flag']);
            unset($_SESSION['form_data_temp']);
            // NEW: Clear CA related session data
            unset($_SESSION['ca_certificate']);
            unset($_SESSION['ca_verification_output']);
            unset($_SESSION['ca_request_status']);
            // Removed $_SESSION['ca_request_log'] from here

            session_write_close();
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit();
        }
    }
}
