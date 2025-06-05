<?php
// openssl_functions.php - OpenSSL Command Execution Logic

require_once 'config.php'; // Access global constants like CERT_DIR

/**
 * Generates OpenSSL configuration content based on submitted form data.
 *
 * @param array $data The submitted form data.
 * @return string The OpenSSL configuration content.
 */
function generate_openssl_cnf_content(array $data): string
{
    $hostname = $data['cn'];
    $alt_names = [];
    $dns_entries = array_filter(array_map('trim', explode(',', $data['dns'])));
    $ip_entries = array_filter(array_map('trim', explode(',', $data['ips'])));

    // Add CN as the first DNS SAN
    $alt_names[] = "DNS.1 = " . $hostname;
    $dns_counter = 2; // Start from 2 as DNS.1 is CN
    foreach ($dns_entries as $dns) {
        if ($dns !== $hostname) { // Avoid duplicating CN if already in DNS list
            $alt_names[] = "DNS." . $dns_counter++ . " = " . $dns;
        }
    }
    $ip_counter = 1;
    foreach ($ip_entries as $ip) {
        $alt_names[] = "IP." . $ip_counter++ . " = " . $ip;
    }

    $openssl_cnf_content = <<<EOT
[req]
distinguished_name = req_distinguished_name
req_extensions = req_cert_extensions
prompt = no
encrypt_key = no
dirstring_type = nombstr
default_bits = 4096
default_keyfile = {$hostname}.key

[req_distinguished_name]
C = {$data['country']}
ST = {$data['state']}
L = {$data['city']}
O = {$data['org']}
OU = {$data['ou']}
CN = {$data['cn']}

[req_cert_extensions]
subjectAltName = @alt_names

[alt_names]\n
EOT;
    $openssl_cnf_content .= implode("\n", $alt_names);

    return $openssl_cnf_content;
}

/**
 * Executes OpenSSL commands to generate private key and CSR.
 *
 * @param array $submitted_data The data submitted from the form.
 * @param bool  $generate_new_key_flag True to generate a new private key, false to use an existing one.
 * @return array An associative array containing:
 * - 'generated_files': array of basenames of generated files (key, csr).
 * - 'generated_file_paths': array of web paths for generated files.
 * - 'openssl_output': array of raw output from openssl commands.
 * - 'generation_status': 'success' or 'fail'.
 * - 'generation_log': detailed log of the generation process.
 * - 'csr_content': The actual content of the generated CSR for API submission.
 */
function generate_certificate_components(array $submitted_data, bool $generate_new_key_flag): array
{
    $generated_files = [];
    $generated_file_paths = [];
    $openssl_output = [];
    $generation_log = '';
    $generation_status = 'fail'; // Default to fail, set to success if all steps pass
    $csr_content = ''; // Initialize CSR content

    $hostname = $submitted_data['cn'];
    $key_file = CERT_DIR . $hostname . '.key';
    $csr_file = CERT_DIR . $hostname . '.csr';
    $openssl_cnf_for_req = CERT_DIR . $hostname . '-openssl.cnf'; // Changed to -openssl.cnf

    $generation_log .= "Attempting to generate certificate components for: " . $hostname . "\n";

    // 1. Generate OpenSSL config file content and save it
    $openssl_cnf_content = generate_openssl_cnf_content($submitted_data);
    file_put_contents($openssl_cnf_for_req, $openssl_cnf_content); // Use the new name
    $generated_files[] = basename($openssl_cnf_for_req);
    $generated_file_paths[] = '/certdir/' . basename($openssl_cnf_for_req);
    $generation_log .= "Generated temporary OpenSSL config: " . basename($openssl_cnf_for_req) . "\n";

    // 2. Generate Private Key (only if $generate_new_key_flag is true)
    if ($generate_new_key_flag) {
        $command_genkey = "openssl genrsa -out " . escapeshellarg($key_file) . " 2048 2>&1";
        $openssl_output['key_gen'] = shell_exec($command_genkey);
        if (file_exists($key_file)) {
            $generated_files[] = basename($key_file);
            $generated_file_paths[] = '/certdir/' . basename($key_file);
            $generation_log .= "Generated NEW private key: " . basename($key_file) . "\n";
        } else {
            $openssl_output['key_gen_error'] = "Failed to generate private key. Output: " . $openssl_output['key_gen'];
            $generation_log .= "ERROR: Failed to generate private key.\nOutput: " . $openssl_output['key_gen'] . "\n";
        }
    } else {
        $generation_log .= "Using EXISTING private key: " . basename($key_file) . "\n";
        if (file_exists($key_file)) {
            $generated_files[] = basename($key_file);
            $generated_file_paths[] = '/certdir/' . basename($key_file);
        } else {
            $openssl_output['key_gen_error'] = "ERROR: Attempted to use existing key, but file not found: " . basename($key_file);
            $generation_log .= "ERROR: Attempted to use existing key, but file not found: " . basename($key_file) . "\n";
            $generation_status = 'fail'; // Mark as fail if existing key is missing
        }
    }

    // 3. Generate CSR (only if key generation was successful or existing key was found)
    if (file_exists($key_file)) { // Proceed with CSR generation only if key file is present
        $command_gencsr = "openssl req -new -key " . escapeshellarg($key_file) .
                          " -out " . escapeshellarg($csr_file) .
                          " -config " . escapeshellarg($openssl_cnf_for_req) . " 2>&1"; // Use the new name
        $openssl_output['csr_gen'] = shell_exec($command_gencsr);
        if (file_exists($csr_file)) {
            $generated_files[] = basename($csr_file);
            $generated_file_paths[] = '/certdir/' . basename($csr_file);
            $generation_log .= "Generated CSR: " . basename($csr_file) . "\n";
            $csr_content = file_get_contents($csr_file); // Read CSR content
        } else {
            $openssl_output['csr_gen_error'] = "Failed to generate CSR. Output: " . $openssl_output['csr_gen'];
            $generation_log .= "ERROR: Failed to generate CSR.\nOutput: " . $openssl_output['csr_gen'] . "\n";
        }
    } else {
        $openssl_output['csr_gen_error'] = "CSR generation skipped: Private key not available.";
        $generation_log .= "ERROR: CSR generation skipped because private key was not generated or found.\n";
    }

    // Determine overall status based on key and CSR generation
    if (empty($openssl_output['key_gen_error']) && empty($openssl_output['csr_gen_error'])) {
        $generation_status = 'success';
    } else {
        $generation_status = 'fail';
    }

    // Clean up temporary OpenSSL config file (uncomment in production)
    // unlink($openssl_cnf_for_req);

    return [
        'generated_files' => $generated_files,
        'generated_file_paths' => $generated_file_paths,
        'openssl_output' => $openssl_output,
        'generation_status' => $generation_status,
        'generation_log' => $generation_log,
        'csr_content' => $csr_content // Return CSR content for AJAX submission
    ];
}
