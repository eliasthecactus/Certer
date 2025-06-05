<?php
// template_parts.php - HTML rendering functions

/**
 * Renders the HTML header section.
 *
 * @param bool $is_authenticated True if the user is authenticated, false otherwise.
 * @return void
 */
function render_header(bool $is_authenticated): void
{
    ?>
    <header class="bg-indigo-600 text-white py-6 shadow-md">
        <div class="container mx-auto px-4 flex justify-between items-center">
            <h1 class="text-3xl font-bold tracking-wide">Certer</h1>
            <?php if ($is_authenticated): ?>
                <form method="POST" class="inline-block">
                    <button type="submit" name="logout"
                            class="bg-indigo-700 hover:bg-indigo-800 text-white px-4 py-2 rounded-lg text-sm font-semibold transition">
                        Logout
                    </button>
                </form>
            <?php endif; ?>
        </div>
    </header>
    <?php
}

/**
 * Renders the login form.
 *
 * @param string|null $login_error An error message to display, or null if none.
 * @return void
 */
function render_login_form(?string $login_error): void
{
    ?>
    <section class="bg-white p-6 rounded-2xl shadow-lg">
        <h2 class="text-2xl font-semibold mb-4 text-center">Login</h2>
        <?php if (isset($login_error)): ?>
            <div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 rounded mb-4">
                <p><?= htmlspecialchars($login_error) ?></p>
            </div>
        <?php endif; ?>
        <form method="POST" class="space-y-4">
            <div>
                <label for="username" class="block font-medium text-gray-700 mb-2">Username</label>
                <input type="text" id="username" name="username" required
                       class="w-full border border-gray-300 rounded-lg px-4 py-2.5
                              focus:ring-indigo-500 focus:border-indigo-500 shadow-sm" />
            </div>
            <div>
                <label for="password" class="block font-medium text-gray-700 mb-2">Password</label>
                <input type="password" id="password" name="password" required
                       class="w-full border border-gray-300 rounded-lg px-4 py-2.5
                              focus:ring-indigo-500 focus:border-indigo-500 shadow-sm" />
            </div>
            <div class="pt-4 flex justify-end">
                <button type="submit" name="login"
                        class="bg-indigo-600 text-white px-6 py-2.5 rounded-lg
                               hover:bg-indigo-700 transition duration-300 ease-in-out
                               shadow-md font-semibold text-lg">
                    Login
                </button>
            </div>
        </form>
    </section>
    <?php
}

/**
 * Renders the multi-step certificate generator form.
 *
 * @param array      $form_data          Current values for form fields.
 * @param int        $current_step       The current step number (1, 2, or 3).
 * @param array|null $submitted_data     Final submitted data for display after generation.
 * @param array      $generated_files    Basenames of generated files.
 * @param array      $generated_file_paths Web paths for download links.
 * @param array      $openssl_output     Raw output from OpenSSL commands.
 * @param string     $generation_status  'success' or 'fail'.
 * @param string     $generation_log     Detailed log of the generation process.
 * @param string     $key_decision_cn    The Common Name for which the key decision is being made (no longer used for step 1.5).
 * @param bool       $generate_new_key_flag True if a new key should be generated (no existing key found), false otherwise.
 * @param string     $ca_certificate         The fetched certificate content.
 * @param string     $ca_verification_output Output from CA certificate verification.
 * @param string     $ca_request_status      Status of the CA request ('success', 'error', 'not_attempted').
 * @return void
 */
function render_generator_form(
    array $form_data,
    int $current_step,
    ?array $submitted_data,
    array $generated_files,
    array $generated_file_paths,
    array $openssl_output,
    string $generation_status,
    string $generation_log,
    string $key_decision_cn,
    bool   $generate_new_key_flag,
    // NEW: CA request related parameters (ca_request_log removed)
    string $ca_certificate,
    string $ca_verification_output,
    string $ca_request_status
): void {
    ?>
    <section class="bg-white p-6 rounded-2xl shadow-lg">
        <h2 class="text-2xl font-semibold mb-4 text-center">Generate Certificate Request</h2>

        <?php if ($current_step === 1): ?>
            <!-- Debug: Inside Step 1 rendering block -->
            <!-- Step 1: Hostname Input -->
            <form method="POST" class="space-y-6">
                <h3 class="text-xl font-medium text-gray-700 mb-3">Step 1 of 3: Enter Common Name</h3>
                <div>
                    <label for="cn" class="block font-medium text-gray-700 mb-2">
                        Common Name <span class="text-red-500">*</span>
                    </label>
                    <input type="text" id="cn" name="cn" required
                           class="w-full border border-gray-300 rounded-lg px-4 py-2.5
                                  focus:ring-indigo-500 focus:border-indigo-500 shadow-sm
                                  placeholder-gray-400 text-gray-800"
                           value="<?= htmlspecialchars($form_data['cn']) ?>"
                           placeholder="e.g., server-323" />
                    <p class="text-sm text-gray-500 mt-1">
                        This is typically hostname (not FQDN) of your server.
                    </p>
                </div>
                <div class="pt-4 flex justify-end">
                    <button type="submit" name="next_step"
                            class="bg-indigo-600 text-white px-6 py-2.5 rounded-lg
                                   hover:bg-indigo-700 transition duration-300 ease-in-out
                                   shadow-md font-semibold text-lg">
                        Next
                    </button>
                </div>
            </form>
        <?php elseif ($current_step === 2): ?>
            <!-- Step 2: Additional Details Input -->
            <form method="POST" class="space-y-6" id="csrForm">
                <h3 class="text-xl font-medium text-gray-700 mb-3">Step 2 of 3: Enter Additional Details</h3>
                <div>
                    <label for="cn_display" class="block font-medium text-gray-700 mb-2">
                        Common Name (CN)
                    </label>
                    <!-- Hidden field to carry CN value in POST request -->
                    <input type="hidden" name="cn_display" value="<?= htmlspecialchars($form_data['cn']) ?>">
                    <input type="text" id="cn_display_readonly" value="<?= htmlspecialchars($form_data['cn']) ?>"
                           class="w-full border border-gray-300 rounded-lg px-4 py-2.5 bg-gray-50 cursor-not-allowed"
                           readonly />
                    <p class="text-sm text-gray-500 mt-1">
                        This is the hostname you entered in the previous step.
                    </p>
                </div>

                <div>
                    <label for="org" class="block font-medium text-gray-700 mb-2">Organization (O)</label>
                    <input type="text" id="org" name="org"
                           class="w-full border border-gray-300 rounded-lg px-4 py-2.5
                                  focus:ring-indigo-500 focus:border-indigo-500 shadow-sm
                                  placeholder-gray-400 text-gray-800"
                           value="<?= htmlspecialchars($form_data['org']) ?>"
                           placeholder="e.g., My Company Inc." />
                    <p class="text-sm text-gray-500 mt-1">
                        The legal name of your organization.
                    </p>
                </div>

                <div>
                    <label for="ou" class="block font-medium text-gray-700 mb-2">Organizational Unit (OU)</label>
                    <input type="text" id="ou" name="ou"
                           class="w-full border border-gray-300 rounded-lg px-4 py-2.5
                                  focus:ring-indigo-500 focus:border-indigo-500 shadow-sm
                                  placeholder-gray-400 text-gray-800"
                           value="<?= htmlspecialchars($form_data['ou']) ?>"
                           placeholder="e.g., IT Department" />
                    <p class="text-sm text-gray-500 mt-1">
                        The division or department within your organization.
                    </p>
                </div>

                <div>
                    <label for="city" class="block font-medium text-gray-700 mb-2">City / Locality (L)</label>
                    <input type="text" id="city" name="city"
                           class="w-full border border-gray-300 rounded-lg px-4 py-2.5
                                  focus:ring-indigo-500 focus:border-indigo-500 shadow-sm
                                  placeholder-gray-400 text-gray-800"
                           value="<?= htmlspecialchars($form_data['city']) ?>"
                           placeholder="e.g., Zurich" />
                    <p class="text-sm text-gray-500 mt-1">
                        The city or locality where your organization is located.
                    </p>
                </div>

                <div>
                    <label for="state" class="block font-medium text-gray-700 mb-2">State / Province (ST)</label>
                    <input type="text" id="state" name="state"
                           class="w-full border border-gray-300 rounded-lg px-4 py-2.5
                                  focus:ring-indigo-500 focus:border-indigo-500 shadow-sm
                                  placeholder-gray-400 text-gray-800"
                           value="<?= htmlspecialchars($form_data['state']) ?>"
                           placeholder="e.g., Zurich" />
                    <p class="text-sm text-gray-500 mt-1">
                        The state or province where your organization is located.
                    </p>
                </div>

                <div>
                    <label for="country" class="block font-medium text-gray-700 mb-2">Country Code (C)</label>
                    <input type="text" id="country" name="country" maxlength="2"
                           class="w-full border border-gray-300 rounded-lg px-4 py-2.5
                                  focus:ring-indigo-500 focus:border-indigo-500 shadow-sm
                                  placeholder-gray-400 text-gray-800"
                           value="<?= htmlspecialchars($form_data['country']) ?>"
                           placeholder="e.g., US" />
                    <p class="text-sm text-gray-500 mt-1">
                        A two-letter country code (e.g., US, GB, DE).
                    </p>
                </div>

                <div>
                    <label for="dns" class="block font-medium text-gray-700 mb-2">
                        Subject Alternative Names (DNS)
                    </label>
                    <textarea id="dns" name="dns" rows="3"
                              class="w-full border border-gray-300 rounded-lg px-4 py-2.5
                                     focus:ring-indigo-500 focus:border-indigo-500 shadow-sm
                                     placeholder-gray-400 text-gray-800"
                              placeholder="e.g., example.com, www.example.com"><?= htmlspecialchars($form_data['dns']) ?></textarea>
                    <p class="text-sm text-gray-500 mt-1">
                        Comma-separated list of additional domain names to secure.
                    </p>
                </div>

                <div>
                    <label for="ips" class="block font-medium text-gray-700 mb-2">
                        Subject Alternative Names (IPs)
                    </label>
                    <textarea id="ips" name="ips" rows="3"
                              class="w-full border border-gray-300 rounded-lg px-4 py-2.5
                                     focus:ring-indigo-500 focus:border-indigo-500 shadow-sm
                                     placeholder-gray-400 text-gray-800"
                              placeholder="e.g., 192.168.1.1, 10.0.0.2"><?= htmlspecialchars($form_data['ips']) ?></textarea>
                    <p class="text-sm text-gray-500 mt-1">
                        Comma-separated list of IP addresses to secure.
                    </p>
                </div>

                <?php if (!$generate_new_key_flag): ?>
                    <!-- This checkbox only appears if a key already exists for the CN -->
                    <div class="flex items-center pt-2">
                        <input type="checkbox" id="force_new_key" name="force_new_key" value="true"
                               class="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded">
                        <label for="force_new_key" class="ml-2 block text-sm text-gray-900">
                            Generate a <strong>new</strong> private key (will overwrite existing for this CN)
                        </label>
                    </div>
                <?php endif; ?>

                <div class="pt-4 flex justify-between">
                    <button type="submit" name="prev_step"
                            class="bg-gray-300 text-gray-800 px-6 py-2.5 rounded-lg
                                   hover:bg-gray-400 transition duration-300 ease-in-out
                                   shadow-md font-semibold text-lg">
                        Back
                    </button>
                    <button type="submit" name="generate_csr"
                            class="bg-indigo-600 text-white px-6 py-2.5 rounded-lg
                                   hover:bg-indigo-700 transition duration-300 ease-in-out
                                   shadow-md font-semibold text-lg">
                        Generate CSR
                    </button>
                </div>
            </form>
        <?php elseif ($current_step === 3): ?>
            <!-- Step 3: Generation Status and Logs & CA Request -->
            <div class="
                <?php if ($generation_status === 'success'): ?>
                    bg-green-100 border-l-4 border-green-500 text-green-700
                <?php elseif ($generation_status === 'fail'): ?>
                    bg-red-100 border-l-4 border-red-500 text-red-700
                <?php endif; ?>
                p-4 rounded mb-6
            ">
                <p class="font-bold text-lg mb-2">
                    <?php if ($generation_status === 'success'): ?>
                        Certificate Request (CSR) and CA Request Processed Successfully!
                    <?php elseif ($generation_status === 'fail'): ?>
                        Certificate Generation Process Failed!
                    <?php endif; ?>
                </p>
                <p>Here's a summary of the information you provided:</p>
                <ul class="list-disc list-inside mt-3 text-sm space-y-1">
                    <li><strong>Common Name:</strong> <?= htmlspecialchars($submitted_data['cn']) ?></li>
                    <li><strong>Organization:</strong> <?= htmlspecialchars($submitted_data['org']) ?></li>
                    <li><strong>Organizational Unit:</strong> <?= htmlspecialchars($submitted_data['ou']) ?></li>
                    <li><strong>City:</strong> <?= htmlspecialchars($submitted_data['city']) ?></li>
                    <li><strong>State:</strong> <?= htmlspecialchars($submitted_data['state']) ?></li>
                    <li><strong>Country:</strong> <?= htmlspecialchars($submitted_data['country']) ?></li>
                    <li><strong>DNS Names:</strong> <?= htmlspecialchars($submitted_data['dns']) ?></li>
                    <li><strong>IP Addresses:</strong> <?= htmlspecialchars($submitted_data['ips']) ?></li>
                </ul>
                <?php if (!empty($generated_files)): ?>
                    <p class="mt-4 font-semibold">Generated Files (in `certdir/`):</p>
                    <ul class="list-disc list-inside mt-1 text-sm space-y-1">
                        <?php foreach ($generated_files as $index => $file_basename): ?>
                            <li>
                                <a href="<?= htmlspecialchars($generated_file_paths[$index]) ?>"
                                   class="text-indigo-600 hover:underline" download>
                                    <?= htmlspecialchars($file_basename)
                                    ?>
                                </a>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>

                <p class="mt-4 font-semibold">Combined Process Log:</p>
                <pre class="bg-gray-800 text-white p-3 rounded-md text-xs overflow-x-auto mt-2"><code><?= htmlspecialchars($generation_log) ?></code></pre>

                <?php if (!empty($openssl_output['key_gen_error']) || !empty($openssl_output['csr_gen_error'])): ?>
                    <div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 rounded mt-4">
                        <p class="font-bold">Summary of OpenSSL Errors during key/CSR generation:</p>
                        <?php if (!empty($openssl_output['key_gen_error'])): ?>
                            <p class="text-sm mt-1"><strong>Private Key Generation Error:</strong> <?= htmlspecialchars($openssl_output['key_gen_error']) ?></p>
                        <?php endif; ?>
                        <?php if (!empty($openssl_output['csr_gen_error'])): ?>
                            <p class="text-sm mt-1"><strong>CSR Generation Error:</strong> <?= htmlspecialchars($openssl_output['csr_gen_error']) ?></p>
                        <?php endif; ?>
                        <p class="text-sm mt-2">Please ensure `openssl` is installed and accessible in your PHP container and has necessary permissions.</p>
                    </div>
                <?php endif; ?>
            </div>

            <?php if ($generation_status === 'success' && !empty($submitted_data['cn'])): ?>
                <p class="mb-4 text-center text-lg font-medium text-gray-700">
                    The certificate has been successfully fetched from your CA.
                </p>
                <div class="bg-white p-6 rounded-2xl shadow-lg mt-8">
                    <h3 class="text-xl font-semibold mb-4 text-center">Certificate from CA</h3>

                    <?php if ($ca_request_status === 'success'): ?>
                        <div class="mt-6 p-4 rounded-md text-sm bg-green-100 text-green-700">
                            <p class="font-bold">Certificate successfully retrieved and verified!</p>
                            <p class="text-sm mt-2">Verification: <span class="text-green-600"><?= htmlspecialchars($ca_verification_output) ?></span></p>
                        </div>
                        <div class="mt-6">
                            <h4 class="text-lg font-semibold mb-2">Received Certificate:</h4>
                            <pre class="bg-gray-800 text-white p-3 rounded-md text-xs overflow-x-auto">
                                <code><?= htmlspecialchars($ca_certificate) ?></code>
                            </pre>
                            <div class="flex justify-start items-center mt-4">
                                <a id="downloadCertLink" href="#" download="<?= htmlspecialchars($submitted_data['cn']) ?>.crt"
                                   class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition">
                                    Download Certificate
                                </a>
                            </div>
                        </div>
                    <?php elseif ($ca_request_status === 'error'): ?>
                        <div class="mt-6 p-4 rounded-md text-sm bg-red-100 text-red-700">
                            <p class="font-bold">Error requesting certificate from CA!</p>
                            <p class="text-sm mt-2">
                                CA Request Status: Failed.
                                <br>Check the "Combined Process Log" above for details.
                            </p>
                        </div>
                    <?php else: // 'not_attempted' ?>
                        <div class="mt-6 p-4 rounded-md text-sm bg-yellow-100 text-yellow-700">
                            <p class="font-bold">Certificate request to CA was not attempted.</p>
                            <p class="text-sm mt-2">Check the "Combined Process Log" above for details.</p>
                        </div>
                    <?php endif; ?>
                </div>

                <?php if ($ca_request_status === 'success'): ?>
                    <script>
                        // Create object URL for download after the page loads
                        document.addEventListener('DOMContentLoaded', () => {
                            const certificateContent = document.querySelector('#certificateContent').textContent;
                            const downloadLink = document.querySelector('#downloadCertLink');
                            if (certificateContent && downloadLink) {
                                const blob = new Blob([certificateContent], { type: 'application/x-x509-ca-cert' });
                                const url = URL.createObjectURL(blob);
                                downloadLink.href = url;
                            }
                        });
                    </script>
                <?php endif; ?>

            <?php endif; ?>

            <div class="pt-4 flex justify-end">
                <?php if ($generation_status === 'fail'): ?>
                    <form method="POST" class="inline-block">
                        <button type="submit" name="done_and_start_over"
                                class="bg-indigo-600 text-white px-6 py-2.5 rounded-lg
                                       hover:bg-indigo-700 transition duration-300 ease-in-out
                                       shadow-md font-semibold text-lg">
                            Done
                        </button>
                    </form>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </section>
    <?php
}

/**
 * Renders the HTML footer section.
 *
 * @return void
 */
function render_footer(): void
{
    ?>
    <footer class="mt-12 py-6 text-center text-sm text-gray-500">
        &copy; 2025 by <a href="https://github.com/eliasthecactus"><strong>eliasthecactus</strong></a>. All rights reserved.
    </footer>
    <?php
}
