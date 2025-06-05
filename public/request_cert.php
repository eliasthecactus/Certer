<?php
// request_cert.php - Handles API requests to fetch a real certificate from a Windows CA

// Include necessary configuration
require_once 'config.php';

// Set content type for JSON responses
header('Content-Type: application/json');

// --- Input Validation ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // Method Not Allowed
    echo json_encode(['error' => 'Only POST requests are allowed.']);
    exit();
}

if (!isset($_POST['csr_content']) || empty($_POST['csr_content'])) {
    http_response_code(400); // Bad Request
    echo json_encode(['error' => 'Missing or empty "csr_content" in POST request.']);
    exit();
}

$csr_content = $_POST['csr_content'];

// Optional: If you want to allow a specific name for the certificate,
// otherwise, you might generate a unique name or use a hash of the CSR.
// Sanitize name to prevent directory traversal or command injection
$cert_name = isset($_POST['cert_name']) && !empty($_POST['cert_name'])
    ? preg_replace('/[^a-zA-Z0-9_\-.]/', '', $_POST['cert_name']) // Allow dots for FQDNs
    : uniqid('cert_'); // Generate a unique name if not provided

$temp_cert_file_path = CERT_DIR . $cert_name . '.crt.tmp'; // Temporary storage for verification

// Ensure 'certdir' exists and is writable by the web server
if (!is_dir(CERT_DIR)) {
    if (!mkdir(CERT_DIR, 0755, true)) {
        http_response_code(500); // Internal Server Error
        echo json_encode(['error' => 'Server error: Could not create "certdir" directory.']);
        exit();
    }
}
if (!is_writable(CERT_DIR)) {
    http_response_code(500); // Internal Server Error
    echo json_encode(['error' => 'Server error: "certdir" is not writable.']);
    exit();
}

// --- Prepare CSR for CA Request ---
// Remove newlines and carriage returns, then URL-encode.
// Specifically handle '+' character which gets converted to space by urlencode and then needs to be converted back to '%2B'
$csr_encoded = str_replace(["\n", "\r"], '', $csr_content);
$csr_encoded = urlencode($csr_encoded);
$csr_encoded = str_replace('+', '%2B', $csr_encoded); // Handle literal '+' signs in the CSR for correct encoding

// Encode certificate template name
$cert_attrib = urlencode("CertificateTemplate:" . CA_TEMPLATE_NAME . "\r\n");

// --- Request Certificate from CA ---
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://" . CA_FQDN . "/certsrv/certfnsh.asp");
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
    $error_msg = "Error requesting certificate from CA: " . curl_error($ch);
    error_log($error_msg);
    http_response_code(500);
    echo json_encode(['error' => $error_msg]);
    curl_close($ch);
    exit();
}
curl_close($ch);

if ($http_code !== 200) {
    $error_msg = "CA request failed with HTTP status {$http_code}. Response: " . substr($response, 0, 500);
    error_log($error_msg);
    http_response_code(502); // Bad Gateway - CA server responded with error
    echo json_encode(['error' => 'Failed to request certificate from CA.', 'ca_response_code' => $http_code, 'ca_response_body' => substr($response, 0, 500)]);
    exit();
}

// --- Parse Response for Certificate Link ---
// The Windows CA typically redirects or provides JS to redirect to the certificate download link
preg_match('/function handleGetCert\(\) {\s*location\.href\s*=\s*"([^"]+)";/s', $response, $matches);

if (!isset($matches[1])) {
    $error_msg = "Could not find certificate retrieval link in CA response. Response: " . substr($response, 0, 500);
    error_log($error_msg);
    http_response_code(500);
    echo json_encode(['error' => 'Failed to parse CA response for certificate link.']);
    exit();
}
$output_link = $matches[1];
$cert_link = "https://" . CA_FQDN . "/certsrv/{$output_link}";


// --- Retrieve Certificate ---
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
    $error_msg = "Error retrieving certificate: " . curl_error($ch);
    error_log($error_msg);
    http_response_code(500);
    echo json_encode(['error' => $error_msg]);
    curl_close($ch);
    exit();
}
curl_close($ch);

if ($http_code !== 200) {
    $error_msg = "CA retrieval failed with HTTP status {$http_code}. Response: " . substr($certificate_data, 0, 500);
    error_log($error_msg);
    http_response_code(502); // Bad Gateway
    echo json_encode(['error' => 'Failed to retrieve certificate from CA.', 'ca_response_code' => $http_code, 'ca_response_body' => substr($certificate_data, 0, 500)]);
    exit();
}

// --- Save for Verification and Cleanup ---
// Save the raw certificate data to a temporary file
if (file_put_contents($temp_cert_file_path, $certificate_data) === false) {
    $error_msg = "Server error: Could not save certificate to '{$temp_cert_file_path}' for verification.";
    error_log($error_msg);
    http_response_code(500);
    echo json_encode(['error' => $error_msg]);
    exit();
}

// --- Verify Certificate ---
// OpenSSL verification command
$command = "openssl verify -verbose " . escapeshellarg($temp_cert_file_path) . " 2>&1";
exec($command, $output, $return_var);
$verification_output = implode("\n", $output);

// --- Clean up temporary certificate file ---
// unlink($temp_cert_file_path); // Uncomment in production to remove temp file after use

if ($return_var === 0) {
    // Success: Return the certificate
    http_response_code(200); // OK
    echo json_encode([
        'status' => 'success',
        'certificate' => $certificate_data,
        'verification_output' => $verification_output
    ]);
} else {
    // Verification failed: Return error
    $error_msg = "Certificate verification failed. OpenSSL error code: {$return_var}. Output: " . $verification_output;
    error_log($error_msg);
    http_response_code(422); // Unprocessable Entity (Semantic error in the certificate)
    echo json_encode([
        'status' => 'error',
        'message' => 'Certificate verification failed after retrieval.',
        'verification_error' => $verification_output,
        'openssl_return_code' => $return_var
    ]);
}
