<?php
// --- Authentication Configuration ---
define('AUTH_USERNAME', getenv('AUTH_USERNAME') ?: 'admin');
define('AUTH_PASSWORD', getenv('AUTH_PASSWORD') ?: 'password');
define('AUTH_TIMEOUT_SECONDS', 4 * 3600);

// --- Certificate Directory Configuration ---
define('CERT_DIR', __DIR__ . '/certdir/');
if (!is_dir(CERT_DIR)) {
    mkdir(CERT_DIR, 0755, true);
}

// --- Default Form Values ---
$default_form_values = [
    'org'     => getenv('DEFAULT_ORG')     ?: 'YourOrg',
    'ou'      => getenv('DEFAULT_OU')      ?: 'YourOu',
    'city'    => getenv('DEFAULT_CITY')    ?: 'YourCity',
    'state'   => getenv('DEFAULT_STATE')   ?: 'YourState',
    'country' => getenv('DEFAULT_COUNTRY') ?: 'CH',
];

// --- Certificate Authority (CA) Configuration ---
define('CA_FQDN', getenv('CA_FQDN') ?: 'your-server.domain.ch');
define('CA_USERNAME', getenv('CA_USERNAME') ?: 'username');
define('CA_PASSWORD', getenv('CA_PASSWORD') ?: 'password');
define('CA_TEMPLATE_NAME', getenv('CA_TEMPLATE_NAME') ?: 'YourTemplate');