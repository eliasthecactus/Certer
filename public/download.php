<?php
session_start(); // Start the session to access authentication status

require_once 'config.php'; // Include configuration for CERT_DIR
require_once 'auth.php';   // Include authentication functions

// 1. Authentication Check: Ensure only logged-in users can download files.
if (!is_user_authenticated()) {
    http_response_code(401); // Send Unauthorized status
    die("Unauthorized access. Please log in to download files.");
}

// 2. Get Filename from URL Parameter
$filename = $_GET['file'] ?? '';

// 3. Validate Filename and Prevent Directory Traversal
if (empty($filename)) {
    http_response_code(400); // Send Bad Request status
    die("File parameter is missing.");
}

// Use basename() to remove any directory components from the filename.
// This is a critical security measure to prevent directory traversal attacks
// (e.g., trying to download ../../../etc/passwd).
$filename = basename($filename);

// Construct the full, absolute path to the file within the allowed certificate directory.
$filepath = CERT_DIR . $filename;

// 4. Check if File Exists and is Readable
if (!file_exists($filepath) || !is_readable($filepath)) {
    http_response_code(404); // Send Not Found status
    die("File not found or not accessible.");
}

// 5. Set HTTP Headers for File Download
// Content-Description: For informational purposes
header('Content-Description: File Transfer');
// Content-Type: Forces browser to download as a generic binary file.
// You could use specific types like 'application/x-x509-ca-cert' for .crt,
// 'application/x-pem-file' for .key/.csr, but octet-stream is safest for general download.
header('Content-Type: application/octet-stream');
// Content-Disposition: Tells the browser to download the file and suggests a filename.
header('Content-Disposition: attachment; filename="' . $filename . '"');
// Expires: Prevent caching
header('Expires: 0');
// Cache-Control: Further directives to prevent caching
header('Cache-Control: must-revalidate');
// Pragma: Compatibility for older HTTP/1.0 clients
header('Pragma: public');
// Content-Length: Tells the browser the size of the file for progress bars
header('Content-Length: ' . filesize($filepath));

// 6. Clear Output Buffer and Send File
// ob_clean() clears the output buffer, preventing any accidental whitespace or
// PHP errors from being sent before the file content, which could corrupt the download.
ob_clean();
// flush() forces the buffered output to be sent to the browser immediately.
flush();
// readfile() reads a file and writes it to the output buffer.
readfile($filepath);

// 7. Exit Script
// Exit immediately after sending the file to prevent any further output.
exit;
