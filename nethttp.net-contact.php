<?php

/**
 * Plugin Name: nethttp.net-contact
 * Plugin URI: https://github.com/yrbane/nethttp.net-contact
 * Description: A custom contact form plugin for WordPress. Once the plugin is activated, you can use the `[custom_contact_form]` shortcode to embed a contact form on your posts or pages.
 * Version: 1.3
 * Author: Barney <yrbane@nethttp.net>
 * Author URI: https://github.com/yrbane
 * Requires PHP: 7.4
 * Text Domain: default
 * License: GPLv3
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Domain Path:       /languages
 */

/**
 * Class Custom_Contact_Form
 *
 * A custom contact form plugin for WordPress.
 *
 * @version 1.3
 * @author yrbane@nethttp.net
 */
class Custom_Contact_Form
{

    /**
     * Blacklist of country codes to block.
     * @var array
     */
    private $DefaultBlacklistedCountries = ['RU', 'CN', 'IN', 'VN', 'NG', 'ID', 'BR', 'KR', 'PK', 'UA']; // Add other country codes if necessary

    /**
     * reCAPTCHA site key.
     * @var string
     */
    private string $recaptcha_site_key = '';

    /**
     * reCAPTCHA secret key.
     * @var string
     */
    private string $recaptcha_secret_key = '';


    /**
     * Custom_Contact_Form constructor.
     *
     * Initializes the plugin.
     *
     * @since 1.0.0
     */
    public function __construct()
    {
        /**
         *  @since 1.1
         */
        add_action('init', [$this, 'set_locale']);

        // Generate a unique form token for each session
        $this->generate_form_token();

        // Register the shortcode for rendering the contact form
        add_shortcode('custom_contact_form', [$this, 'render_contact_form']);

        // Add the admin menu and initialize settings
        add_action('admin_menu', [$this, 'add_admin_page']);
        add_action('admin_init', [$this, 'admin_init']);

        // Add action to display activation message
        add_action('admin_notices', [$this, 'activation_message']);

        // Add action to display admin stylesheets and scripts
        add_action('admin_enqueue_scripts', [$this, 'admin_enqueue_scripts']);

        // Add action to handle activation message dismissal
        add_action('admin_init', [$this, 'hide_activation_message']);

        // Add action to save customised CSS
        add_action('admin_init', [$this, 'saveCustomCss']);

        /**
         *  @since 1.2.2
         */
        add_filter('wp_mail_content_type', [$this, 'set_email_content_type']);


        $this->recaptcha_site_key = get_option('recaptcha_site_key');
        $this->recaptcha_secret_key = get_option('recaptcha_secret_key');
    }

    /**
     * Set the plugin's locale.
     *
     * This method sets the locale for the plugin's translation files based on the site's current locale
     * and any filters applied to the 'plugin_locale' hook.
     *
     * @since 1.1
     */
    public function set_locale()
    {
        $domain = 'default';
        $locale = apply_filters('plugin_locale', get_locale(), $domain);
        load_plugin_textdomain($domain, false, basename(dirname(__FILE__)) . '/languages');
    }


    /**
     * Set the email content type to "text/html".
     *
     * This method sets the content type for email messages to "text/html".
     * 
     *  @since 1.2.2
     *
     * @return string The email content type, which is "text/html".
     */
    public function set_email_content_type(): string
    {
        return "text/html";
    }

    /**
     * Enqueues the admin stylesheet.
     * @since 1.0.0
     */
    public function admin_enqueue_scripts(): void
    {
        wp_enqueue_style('activation-message', plugin_dir_url(__FILE__) . 'css/activation-message.css');
    }

    function add_google_recaptcha_script()
    {
        echo '<script src="https://www.google.com/recaptcha/api.js"></script>';
    }

    /**
     * Function to display a welcome message on plugin activation.
     * @since 1.0.0
     */
    public function activation_message(): void
    {
        // Check if the option to hide the activation message is not set
        if (!get_option('custom_contact_form_hide_activation_message')) {

            printf(
                '<div class="notice notice-success is-dismissible custom-activation-message">
                    <p><strong>🤩 %s Custom Contact Form plugin!</strong></p>
                    <p>%s <a href="%s">Custom Contact Form %s</a> page.</p>
                    <p>%s</p>
                    <form method="post" action=""><button type="submit" name="custom_contact_form_hide_activation_message" value="1" class="button">%s</button></form>
                  </div>',
                __('Thank you for installing the '),
                __('To configure the plugin settings, please visit the'),
                admin_url('admin.php?page=custom_contact_form_settings'),
                __('Settings'),
                __('Add the shortcode [custom_contact_form] to display the form.'),
                __('Don\'t show this message again')

            );
        }
    }

    /**
     * Function to handle hiding the activation message.
     * @since 1.0.0
     */
    public function hide_activation_message(): void
    {
        // Check if the option to hide the activation message has been checked
        if (isset($_POST['custom_contact_form_hide_activation_message']) && $_POST['custom_contact_form_hide_activation_message'] === '1') {
            update_option('custom_contact_form_hide_activation_message', '1');
        }
    }

    /**
     * Generates a form token and stores it in the session.
     * @since 1.0.0
     */
    private function generate_form_token(): void
    {
        if (!isset($_SESSION)) {
            session_start();
        }

        // Generate and store the token in the session if it doesn't exist already
        if (!isset($_SESSION['contact_form_token'])) {
            $_SESSION['contact_form_token'] = bin2hex(random_bytes(16));
        }
    }

    /**
     * Renders the contact form HTML.
     * @since 1.0.0
     * @return string
     */
    public function render_contact_form(): string
    {
        // Enqueue the CSS for the custom contact form
        wp_enqueue_style('custom-contact-form', plugin_dir_url(__FILE__) . 'css/custom-contact-form.css');

        // Add the reCAPTCHA script
        if (!empty($this->recaptcha_site_key) && !empty($this->recaptcha_secret_key)) {
            add_action('wp_head', [$this, 'add_google_recaptcha_script']);
        }

        // Start output buffering to capture the form HTML
        ob_start();

        $send_result = false;
        if (isset($_POST['contact_form_token'])) {

            $recaptcha_response = true;
            if (!empty($this->recaptcha_site_key) && !empty($this->recaptcha_secret_key)) {
                $recaptcha_response = $this->verifyReCAPTCHA();
            }

            if ($recaptcha_response) {
                // Process the contact form if the token is present in the POST data
                $send_result = $this->process_contact_form();
            }
        }

        if (!$send_result) {
            // Initialize form data from previous submissions or empty values
            $data = $this->initialize_form_data(); // Output the HTML form with placeholders for data
            printf(
                '<form method="post" action="#" class="custom-contact-form" >
                    <div>
                        <input type="hidden" name="contact_form_token" value="%s">
                        %s
                        <!-- Name input -->
                        <div class="mb-3">
                            <label class="form-label" for="contact_form_name">' . __('Name') . '</label>
                            <input class="form-control" id="contact_form_name" name="contact_form_name" type="text" value="%s" placeholder="' . __('Name') . '" />
                        </div>
                        <!-- Email address input -->
                        <div class="mb-3">
                            <label class="form-label" for="contact_form_email">' . __('Email Address') . '</label>
                            <input class="form-control" id="contact_form_email" name="contact_form_email" type="email" value="%s" placeholder="' . __('Email Address') . '" />
                        </div>
                        <!-- Tel input -->
                        <div class="mb-3">
                            <label class="form-label" for="contact_form_phone">' . __('Phone') . '</label>
                            <input class="form-control" id="contact_form_phone" name="contact_form_phone" type="tel" value="%s" placeholder="' . __('Phone') . '" />
                        </div>
                        <!-- Message input -->
                        <div class="mb-3">
                            <label class="form-label" for="contact_form_message">' . __('Message') . '</label>
                            <textarea class="form-control" id="contact_form_message" name="contact_form_message" type="text" placeholder="' . __('Message') . '" style="height: 10rem;">%s</textarea>
                        </div>

                        ' .
                    (!empty($this->recaptcha_site_key) && !empty($this->recaptcha_secret_key) ?
                        '<div class="g-recaptcha" data-sitekey="' . $this->recaptcha_site_key . '"></div>' : ''
                    )
                    . '
<br/>
                        <!-- Form submit button -->
                        <div class="d-grid">
                            <button class="btn btn-primary btn-lg wp-block-button__link wp-element-button button button-primary button-large" id="submitButton" type="submit">' . __('Send') . '</button>
                        </div>
                    </div>
                </form>',
                $_SESSION['contact_form_token'],
                wp_nonce_field('contact', 'contact_form_nonce'),
                $data['name'],
                $data['email'],
                $data['phone'],
                $data['message']
            );
        }

        return ob_get_clean();
    }

    private function verifyReCAPTCHA(): bool
    {
        $recaptcha_response = $_POST['g-recaptcha-response'];

        $url = 'https://www.google.com/recaptcha/api/siteverify';
        $data = array(
            'secret' => $this->recaptcha_secret_key,
            'response' => $recaptcha_response
        );

        $options = array(
            'http' => array(
                'method' => 'POST',
                'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                'content' => http_build_query($data)
            )
        );

        $context  = stream_context_create($options);
        $verify = file_get_contents($url, false, $context);
        $captcha_success = json_decode($verify);

        if ($captcha_success->success) {
            return true;
        } else {
            $this->display_error_message(__('Invalid reCAPTCHA, try again...'));
        }
        return false;
    }

    /**
     * Initialize the form data
     * @since 1.0.0
     * @return array
     */
    private function initialize_form_data(): array
    {
        $data = [
            'name' => '',
            'email' => '',
            'phone' => '',
            'message' => ''
        ];

        if (isset($_POST['contact_form_name'])) {
            $data['name'] = $_POST['contact_form_name'];
        }

        if (isset($_POST['contact_form_email'])) {
            $data['email'] = $_POST['contact_form_email'];
        }

        if (isset($_POST['contact_form_phone'])) {
            $data['phone'] = $_POST['contact_form_phone'];
        }

        if (isset($_POST['contact_form_message'])) {
            $data['message'] = $_POST['contact_form_message'];
        }

        return $data;
    }

    /**
     * Adds the admin menu page for plugin settings.
     * @since 1.0.0
     */
    public function add_admin_page(): void
    {
        add_menu_page(
            'Custom Contact Form' . __('Settings'),
            __('Contact Form'),
            'manage_options',
            'custom_contact_form_settings',
            [$this, 'render_admin_page']
        );
    }

    /**
     * Renders the admin settings page.
     * @since 1.0.0
     */
    public function render_admin_page(): void
    {
?><div class="wrap">
            <h2>Custom Contact Form <?php echo __('Settings'); ?></h2>
            <form action="options.php" method="post">
                <?php
                settings_fields('custom_contact_form_group') .
                    do_settings_sections('custom_contact_form_settings') .
                    submit_button();
                ?>

            </form>
        </div>
<?php
    }

    /**
     * Initializes admin settings.
     * @since 1.0.0
     */
    public function admin_init(): void
    {
        register_setting(
            'custom_contact_form_group',
            'custom_contact_form_email',
            [$this, 'sanitize_email_addresses']
        );

        register_setting(
            'custom_contact_form_group',
            'recaptcha_site_key'
        );

        register_setting(
            'custom_contact_form_group',
            'recaptcha_secret_key'
        );

        add_settings_section(
            'custom_contact_form_section',
            __('Email Settings'),
            [$this, 'section_callback'],
            'custom_contact_form_settings'
        );

        add_settings_section(
            'custom_contact_form_recaptcha_section',
            __('reCAPTCHA Settings'),
            [$this, 'recaptcha_section_callback'],
            'custom_contact_form_settings'
        );


        add_settings_field(
            'custom_contact_form_email',
            __('Destination Email(s)'),
            [$this, 'email_field_callback'],
            'custom_contact_form_settings',
            'custom_contact_form_section'
        );

        // Add a field for the blacklist in the admin settings
        add_settings_field(
            'custom_contact_form_blacklist',
            __('Blacklisted Countries'),
            [$this, 'render_blacklist_field'],
            'custom_contact_form_settings',
            'custom_contact_form_section'
        );

        add_settings_field(
            'recaptcha_site_key',
            'reCAPTCHA Site Key',
            [$this, 'recaptcha_site_key_callback'],
            'custom_contact_form_settings',
            'custom_contact_form_recaptcha_section'
        );

        add_settings_field(
            'recaptcha_secret_key',
            'reCAPTCHA Secret Key',
            [$this, 'recaptcha_secret_key_callback'],
            'custom_contact_form_settings',
            'custom_contact_form_recaptcha_section'
        );

        // Register custom CSS customization settings
        $this->register_custom_css_settings();
    }

    /**
     * Callback for the settings section.
     * @since 1.0.0
     */
    public function section_callback(): void
    {
        echo __('Enter the email(s) address(es) where contact form submissions should be sent.');
    }

    /**
     * Callback for the email settings field.
     * @since 1.0.0
     */
    public function email_field_callback(): void
    {
        $value = get_option('custom_contact_form_email');
        $emails = explode(',', $value);

        foreach ($emails as $email) {
            $email = trim($email);
            if (!empty($email) && !is_email($email)) {
                printf(
                    '<div class="error-message">' . __('Invalid email address') . ': %s</div>',
                    esc_html($email)
                );
            }
        }
        printf(
            '<input type="text" name="custom_contact_form_email" value="%s" />',
            esc_attr($value)
        );
        echo '<p class="description">' . __('Enter multiple email addresses separated by commas.') . '</p>';
    }

    /**
     * Sanitizes and validates the email addresses when saving the settings.
     *
     * This method is responsible for sanitizing and validating a comma-separated list of email addresses.
     * It ensures that each email address is properly formatted and removes any invalid ones.
     *
     * @param string $value The input value containing comma-separated email addresses.
     *
     * @return string A sanitized and validated list of email addresses, separated by commas.
     *
     * @since 1.0.0
     */
    public function sanitize_email_addresses($value): string
    {
        $emails = explode(',', $value);

        $valid_emails = array();
        foreach ($emails as $email) {
            $email = trim($email);
            if (!empty($email) && is_email($email)) {
                $valid_emails[] = $email;
            } else {
                add_settings_error(
                    'custom_contact_form_email',
                    'invalid-email',
                    sprintf(__('Invalid email address') . ': %s', esc_html($email)),
                    'error'
                );
            }
        }

        if (empty($valid_emails)) {
            add_settings_error(
                'custom_contact_form_email',
                'invalid-email',
                __('Please enter at least one valid email address.'),
                'error'
            );
            return get_option('custom_contact_form_email'); // Revert to the previous value
        }

        return implode(',', $valid_emails);
    }

    /**
     * Callback function to render the blacklist field.
     *
     * @return void
     * @since 1.0.0
     */
    function render_blacklist_field(): void
    {
        $blacklist = get_option('custom_contact_form_blacklist', implode(',', $this->DefaultBlacklistedCountries));
        echo '<input type="text" name="custom_contact_form_blacklist" value="' . esc_attr($blacklist) . '" />';
        echo '<p class="description">' . __('Enter a comma-separated list of country codes to blacklist.') . '</p>';
    }

    /**
     * Register the setting for the blacklist.
     *
     * @return void
     * @since 1.0.0
     */
    function register_blacklist_setting(): void
    {
        register_setting('custom_contact_form_group', 'custom_contact_form_blacklist');
    }

    /**
     * Callback to display the reCAPTCHA Site Key field.
     *
     * This function is used to display the reCAPTCHA Site Key input field
     * on the contact form's admin settings page.
     * @return void
     * @since 1.3.0
     */
    public function recaptcha_site_key_callback(): void
    {
        $site_key = get_option('recaptcha_site_key', '');
        echo '<input type="text" id="recaptcha_site_key" name="recaptcha_site_key" value="' . esc_attr($site_key) . '" />';
    }

    /**
     * Callback to display the reCAPTCHA Secret Key field.
     *
     * This function is used to display the reCAPTCHA Secret Key input field
     * on the contact form's admin settings page.
     * @return void
     * @since 1.3.0
     */
    public function recaptcha_secret_key_callback(): void
    {
        $secret_key = get_option('recaptcha_secret_key', '');
        echo '<input type="text" id="recaptcha_secret_key" name="recaptcha_secret_key" value="' . esc_attr($secret_key) . '" />';
    }

    /**
     * Callback for the reCAPTCHA settings section.
     *
     * This function is used to display a description of the reCAPTCHA settings section
     * on the contact form's admin settings page.
     * @return void
     * @since 1.3.0 
     */
    public function recaptcha_section_callback(): void
    {
        echo __('Configure reCAPTCHA settings for your form.');
    }

    /**
     * Register custom CSS settings
     * 
     * @return void
     * @since 1.2
     */
    public function register_custom_css_settings(): void
    {
        register_setting(
            'custom_contact_form_group',
            'custom_contact_form_custom_css',
            [$this, 'sanitize_custom_css']
        );

        add_settings_section(
            'custom_contact_form_css_section',
            __('Custom CSS'),
            [$this, 'css_section_callback'],
            'custom_contact_form_settings'
        );

        add_settings_field(
            'custom_contact_form_custom_css',
            __('Custom CSS Code'),
            [$this, 'custom_css_field_callback'],
            'custom_contact_form_settings',
            'custom_contact_form_css_section'
        );
    }

    /**
     * Callback for the CSS section.
     *
     * Allows customization of the form's appearance by entering your own CSS here.
     *
     * @since 1.2
     */
    public function css_section_callback(): void
    {
        echo __('Customize the form\'s appearance by entering your own CSS here.');
    }

    /**
     * Callback for the custom CSS customization field.
     * 
     * Displays a textarea for users to enter their custom CSS styles.
     * 
     * @since 1.2
     */
    public function custom_css_field_callback(): void
    {
        // Get the custom CSS from the plugin settings
        $custom_css = get_option('custom_contact_form_custom_css', file_get_contents(__DIR__ . '/css/custom-contact-form.css'));

        // Display the textarea with the custom CSS
        echo '<textarea name="custom_contact_form_custom_css" rows="8" cols="50">' . esc_textarea($custom_css) . '</textarea>';
    }

    /**
     * Sanitises custom CSS on save.
     *
     * @param string $value value to sanitise.
     * @return string sanitised CSS.
     * @since 1.2
     */
    public function sanitize_custom_css($value): string
    {
        /**
         * @todo css validations
         */
        return $value;
    }

    /**
     * Callback for processing and saving custom CSS.
     *
     * @since 1.2
     */
    public function saveCustomCss()
    {
        if (isset($_POST['custom_contact_form_custom_css'])) {
            $customCss = sanitize_text_field($_POST['custom_contact_form_custom_css']);
            update_option('custom_contact_form_custom_css', $customCss);
        }
    }

    /**
     * Process the contact form submission.
     * @since 1.0.0
     */
    public function process_contact_form(): bool
    {
        if (
            $this->is_valid_submission()
        ) {
            $to = get_option('custom_contact_form_email');
            if (empty($to)) {
                $this->display_error_message('No recipient email!');
                return false;
            }

            //Get blacklisted country codes
            $blacklist = explode(',', get_option('custom_contact_form_blacklist', implode(',', $this->DefaultBlacklistedCountries)));

            //Check for ip
            $ipdata = $this->getCountryFromIP($_SERVER['REMOTE_ADDR']);

            if (!empty($blacklist) && in_array($ipdata['country_code'], $blacklist)) {
                $this->display_error_message(__('Unauthorized submission'));
                return false;
            }

            $name = sanitize_text_field($_POST['contact_form_name']);
            $email = sanitize_email($_POST['contact_form_email']);
            $message = esc_textarea($_POST['contact_form_message']);

            unset($_POST['contact_form_name'], $_POST['contact_form_email'], $_POST['contact_form_message']);
            
            $message .= '<hr/>';
            $message .= '<strong>USER AGENT</strong>: ' . $_SERVER['HTTP_USER_AGENT'] . '<br/>';
            foreach ($ipdata as $key => $value) {
                $message .= '<strong>' . $key . '</strong>: ' . $value . '<br/>';
            }

            $message .= '<hr/>';
            foreach ($_POST as $key => $value) {
                $message .= '<strong>' . $key . '</strong>: ' . $value . '<br/>';
            }

            $subject = sprintf('[%s] ' . __('Contact Form Submission from') . ' %s', $_SERVER['HTTP_HOST'], $name);
            $headers = sprintf('From: %s <%s>', $name, $email);

            // Check if the data is not empty
            if (!empty($name) && !empty($email) && !empty($message)) {
                apply_filters('wp_mail_content_type', 'text/html');
                $result = wp_mail($to, $subject, $message, $headers);
                
                apply_filters('wp_mail_content_type', 'text/plain');

                // Check if the email was sent successfully and display a message
                if ($result) {
                    printf('<div class="success-message">✅ ' . __('Your message was sent successfully. Thank you!') . '</div>');
                    return true;
                } else {
                    $this->display_error_message(__('Sorry, there was a problem sending your message. Please try again later.'));
                    return false;
                }
            } else {
                $this->display_error_message(__('Please fill in all required fields.'));
                return false;
            }
        } else {
            $this->display_error_message(__('Unauthorized submission or invalid form token.'));
            return false;
        }
    }

    /**
     * Check if the form submission is valid.
     * @return bool
     * @since 1.0.0
     */
    private function is_valid_submission(): bool
    {
        if (
            wp_verify_nonce($_POST['contact_form_nonce'], 'contact') &&
            $this->is_same_origin_submission() &&
            isset($_POST['contact_form_token']) &&
            $_POST['contact_form_token'] === $_SESSION['contact_form_token'] &&
            !$this->is_proxy()
        ) {
            return true;
        }
        return false;
    }

    /**
     * Check if the submission is from the same origin.
     * @return bool
     * @since 1.0.0
     */
    private function is_same_origin_submission(): bool
    {
        return $_SERVER['HTTP_REFERER'] === $_SERVER["REQUEST_SCHEME"] . '://' . $_SERVER["HTTP_HOST"] . $_SERVER["REQUEST_URI"];
    }

    /**
     * Detects if the user is going through a proxy or a VPN.
     *
     * @return bool True if a proxy or VPN is detected, otherwise False.
     * @since 1.0.0
     */
    function is_proxy(): bool
    {
        // Blacklist of proxy and VPN server IP addresses
        $blacklistedIPs = [
            '1.2.3.4', // Add known IP addresses here
            '5.6.7.8',
        ];

        // Check if the "X-Forwarded-For" header is present
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // Get the originating IP address from the header
            $userIP = $_SERVER['HTTP_X_FORWARDED_FOR'];

            // Check if the IP address is in the blacklist
            if (in_array($userIP, $blacklistedIPs)) {
                return true; // Proxy or VPN detected
            }
        }

        return false; // No proxy or VPN detected
    }


    /**
     * Display an error message.
     *
     * @param string $message The error message to display.
     * @since 1.0.0
     */
    private function display_error_message(string $message): void
    {
        printf('<div class="error-message">⚠️ %s</div>', esc_html($message));
    }

    /**
     * Checks the country of the user's IP address using the hostip.info API.
     *
     * @param string $ip The IP address to check.
     *
     * @return array The country of the IP address or false on error.
     * @since 1.0.0
     */
    private function getCountryFromIP($ip): array
    {
        $api_url = "https://api.hostip.info/get_json.php?ip=$ip";

        // Effectue une requête HTTP pour obtenir les informations de géolocalisation.
        $response = wp_safe_remote_get($api_url);

        if (!is_wp_error($response)) {
            $body = wp_remote_retrieve_body($response);
            $data = (array) json_decode($body);

            if ($data) {
                return $data;
            }
        }

        // En cas d'erreur ou si le pays n'est pas trouvé, retourne false.
        return [
            'country_name' => 'UNKNOWN',
            'country_code' => 'XX',
            'city' => '??',
            'ip' => $ip
        ];
    }
}

new Custom_Contact_Form();
