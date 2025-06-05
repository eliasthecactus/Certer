<?php
// --- Authentication Configuration ---
const AUTH_USERNAME = 'admin';
const AUTH_PASSWORD = 'password'; // todo replace with ldap
const AUTH_TIMEOUT_SECONDS = 4 * 3600; // 4 hours

// --- Certificate Directory Configuration ---
const CERT_DIR = __DIR__ . '/certdir/'; // Directory for host-specific config files and generated certificates

// Ensure the certificate directory exists and is writable.
// This will create the directory if it doesn't exist.
if (!is_dir(CERT_DIR)) {
    mkdir(CERT_DIR, 0755, true); // Create directory recursively with 0755 permissions
}

// --- Default Form Values ---
// These values will pre-fill the inputs when they are empty or first loaded,
// or if no existing config file is found for a host.
$default_form_values = [
    'org' => 'YourOrg',
    'ou' => 'YourOu',
    'city' => 'YourCity',
    'state' => 'YourState',
    'country' => 'CH',
];

// --- Certificate Authority (CA) Configuration ---
const CA_FQDN = 'your-server.domain.ch'; // Replace with your CA's FQDN (e.g., 'ca.example.com')
const CA_USERNAME = 'username'; // Replace with the username for CA authentication (e.g., 'domain\user')
const CA_PASSWORD = 'password'; // Replace with the password for CA authentication
const CA_TEMPLATE_NAME = 'YourTemplate'; // Replace with your certificate template name (e.g., 'WebServer')
