<?php

/**
 * Plugin Name: nethttp.net-contact
 * Plugin URI: https://github.com/yrbane/nethttp.net-contact
 * Description: A custom contact form plugin for WordPress. Once the plugin is activated, you can use the `[custom_contact_form]` shortcode to embed a contact form on your posts or pages.
 * Version: 1.3.3
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
 * @version 1.3.3
 * @author yrbane@nethttp.net
 */
class Custom_Contact_Form
{
    const OPTION_HIDE_ACTIVATION_MESSAGE = 'custom_contact_form_hide_activation_message';
    const OPTION_BLACKLISTED_COUNTRIES = 'custom_contact_form_blacklist';
    const OPTION_RECIPIENT_EMAILS = 'custom_contact_form_email';
    const OPTION_RECAPTCHA_SITE_KEY = 'recaptcha_site_key';
    const OPTION_RECAPTCHA_SECRET_KEY = 'recaptcha_secret_key';
    const OPTION_CUSTOM_CSS = 'custom_contact_form_custom_css';
    const OPTION_CUSTOM_CONTACT_FORM_ID = 'custom_contact_form';

    /**
     * @const string banned ips table name
     */
    const BANNED_IPS_TABLE_NAME = 'banned_ips';

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
     * @var wpdb
     */
    private $wpdb;

    /**
     * Custom_Contact_Form constructor.
     *
     * Initializes the plugin.
     *
     * @since 1.0.0
     */
    public function __construct()
    {
        global $wpdb;

        $this->wpdb = $wpdb;

        // Generate a unique form token for each session
        $this->generate_form_token();


        $this->initWordpressHooks();

        $this->recaptcha_site_key = get_option(self::OPTION_RECAPTCHA_SITE_KEY);
        $this->recaptcha_secret_key = get_option(self::OPTION_RECAPTCHA_SECRET_KEY);

        // Ask user if they want to delete all plugin data
        if (isset($_GET['delete_plugin_data']) && $_GET['delete_plugin_data'] === 'true') {
            $this->delete_plugin_data();
        }
    }

    /**
     * Initializes WordPress hooks.
     *
     * @since 1.3.3
     */
    private function initWordpressHooks(): void
    {
        add_action('init', [$this, 'set_locale']);

        // Register the shortcode for rendering the contact form
        add_shortcode('custom_contact_form', [$this, 'render_contact_form']);

        // Add the admin menu and initialize settings
        add_action('admin_menu', [$this, 'add_admin_page']);

        // Add action to initialize admin settings
        add_action('admin_init', [$this, 'admin_init']);

        // Add action to display activation message
        add_action('admin_notices', [$this, 'activation_message']);

        // Add action to display admin stylesheets and scripts
        add_action('admin_enqueue_scripts', [$this, 'admin_enqueue_scripts']);

        // Add action to handle activation message dismissal
        add_action('admin_init', [$this, 'hide_activation_message']);

        // Add action to save customised CSS
        add_action('admin_init', [$this, 'saveCustomCss']);

        // Add action to send email
        add_filter('wp_mail_content_type', [$this, 'set_email_content_type']);

        // Add action on plugin activation
        register_activation_hook(__FILE__, [$this, 'on_activation']);

        // Add action on plugin deactivation
        register_deactivation_hook(__FILE__, [$this, 'on_deactivation']);
    }

    /**
     * Called on plugin activation.
     * @since 1.3.3
     *
     */
    public function on_activation(): void
    {
        // Set the default blacklist
        update_option(self::OPTION_BLACKLISTED_COUNTRIES, implode(',', $this->DefaultBlacklistedCountries));

        // Set the default custom CSS
        update_option(self::OPTION_CUSTOM_CSS, file_get_contents(__DIR__ . '/css/custom-contact-form.css'));

        // Create a database table for storing banned IPs
        $this->create_banned_ips_table();
    }

    /**
     * Called on plugin deactivation.
     * @since 1.3.3
     * @return void
     */
    public function on_deactivation(): void
    {   // Display a confirmation message and a link to delete all plugin data.
        printf(
            '<div class="notice notice-warning is-dismissible custom-activation-message">
                <p><strong>🤔 %s Custom Contact Form plugin!</strong></p>
                <p>%s <a href="%s">Custom Contact Form %s</a> page.</p>
                <p>%s</p>
                <form method="get" action=""><button type="submit" name="delete_plugin_data" value="true" class="button">%s</button></form>
              </div>',
            __('You are about to deactivate the'),
            __('To delete all plugin data, please visit the'),
            admin_url('admin.php?page=custom_contact_form_settings'),
            __('Settings'),
            __('This will delete all plugin data, including the blacklist and all banned IPs.'),
            __('Delete all plugin data')
        );
    }

   
    /**
     * Delete all plugin data.
     * @since 1.3.3
     * @return void
     * @throws Exception
     */
    private function delete_plugin_data(): void
    {
        if(WP_DEBUG){
            return;
        }    
        // Delete all options
        delete_option(self::OPTION_HIDE_ACTIVATION_MESSAGE);
        delete_option(self::OPTION_BLACKLISTED_COUNTRIES);
        delete_option(self::OPTION_RECIPIENT_EMAILS);
        delete_option(self::OPTION_RECAPTCHA_SITE_KEY);
        delete_option(self::OPTION_RECAPTCHA_SECRET_KEY);
        delete_option(self::OPTION_CUSTOM_CSS);

        // Delete the banned IPs table
        $this->delete_banned_ips_table();
    }

    /**
     * Deletes the database table for storing banned IPs.
     * @since 1.3.3
     */
    private function delete_banned_ips_table(): void
    {
        $table_name = $this->wpdb->prefix . self::BANNED_IPS_TABLE_NAME;
        $sql = "DROP TABLE IF EXISTS $table_name;";
        $this->wpdb->query($sql);
    }

    /**
     * Creates a database table for storing banned IPs. With IP,USER AGENT, Country Code, city, Date, used emails (as json) if these are known.
     * @since 1.3.3
     */
    private function create_banned_ips_table(): void
    {
        $table_name = $this->wpdb->prefix . self::BANNED_IPS_TABLE_NAME;
        $charset_collate = $this->wpdb->get_charset_collate();
        $sql = "CREATE TABLE IF NOT EXISTS $table_name (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip varchar(55) NOT NULL,
            user_agent varchar(255) NOT NULL,
            country_name varchar(255) NOT NULL,
            country_code varchar(2) NOT NULL,
            city varchar(255) NOT NULL,
            `date` datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            email varchar(255) NOT NULL,
            `message` text NOT NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }

    /**
     * SQL Query wrapper to execute and log all queries on banned_ips table.
     * Return results of the query.
     * @param string $sql
     * @return array     *
     */
    private function query(string $sql,$sql_param=null): array
    {
        $table_name = $this->wpdb->prefix . self::BANNED_IPS_TABLE_NAME;
        if(is_null($sql_param)){
            $this->wpdb->query(sprintf($sql, $table_name));
        }
        else{
            $sql = $this->wpdb->prepare( $sql , $sql_param );
            return $this->wpdb->get_results( $sql );
        }
        
        
        return $this->wpdb->last_result;
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

    /**
     * Function to display a welcome message on plugin activation.
     * @since 1.0.0
     */
    public function activation_message(): void
    {
        // Check if the option to hide the activation message is not set
        if (!get_option(self::OPTION_HIDE_ACTIVATION_MESSAGE)) {

            printf(
                '<div class="notice notice-success is-dismissible custom-activation-message">
                    <p><strong>🤩 %s Custom Contact Form plugin!</strong></p>
                    <p>%s <a href="%s">Custom Contact Form %s</a> page.</p>
                    <p>%s</p>
                    <form method="post" action=""><button type="submit" name="' . self::OPTION_HIDE_ACTIVATION_MESSAGE . '" value="1" class="button">%s</button></form>
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
        if (isset($_POST[self::OPTION_HIDE_ACTIVATION_MESSAGE]) && $_POST[self::OPTION_HIDE_ACTIVATION_MESSAGE] === '1') {
            update_option(self::OPTION_HIDE_ACTIVATION_MESSAGE, '1');
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

        // Don't display the form if ip is banned
        if ($this->is_ip_banned($_SERVER['REMOTE_ADDR'])) {
            $this->display_error_message(__('Unauthorized submission'));
            return ob_get_clean();
        }

        if (!$send_result) {
            // Initialize form data from previous submissions or empty values
            $data = $this->initialize_form_data(); // Output the HTML form with placeholders for data
            printf(
                '<form method="post" action="?spam=true" class="custom-contact-form" id="' . self::OPTION_CUSTOM_CONTACT_FORM_ID . '">
                    <div>
                        <input type="hidden" id="contact_form_token" name="contact_form_token" value="%s">
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
                        '<script src="https://www.google.com/recaptcha/api.js"></script><div class="g-recaptcha" data-sitekey="' . $this->recaptcha_site_key . '"></div>' : ''
                    )
                    . '
<br/>
                        <!-- Form submit button -->
                        <div class="d-grid">
                            <button class="btn btn-primary btn-lg wp-block-button__link wp-element-button button button-primary button-large" id="submitButton" type="submit">' . __('Send') . '</button>
                        </div>
                    </div>
                </form>',
                'DefaultToken', //Wait a few seconds before filling the token value by JS
                wp_nonce_field('contact', 'contact_form_nonce'),
                $data['name'],
                $data['email'],
                $data['phone'],
                $data['message']
            );
        }
        $this->renderContactFormScript();
        return ob_get_clean();
    }

    /**
     * Renders the contact form script.
     * @since 1.0.0
     */
    private function renderContactFormScript(): void
    {
?>
        <script>
            let contactFormId = "<?php echo self::OPTION_CUSTOM_CONTACT_FORM_ID; ?>";
            let sessionToken = "<?php echo $_SESSION['contact_form_token']; ?>";
            document.addEventListener("DOMContentLoaded", function() {

                setTimeout(function() {
                    //For more security wait 5 seconds before filling the session token value
                    document.getElementById("contact_form_token").value = sessionToken;

                    //Change the submit action of the form to the current page
                    document.getElementById(contactFormId).setAttribute("action", window.location.href);

                }, 5000);

                //Submit the form
                document.getElementById(contactFormId).addEventListener("submit", function(event) {
                    event.preventDefault();
                    if (document.getElementById("contact_form_name").value === "") {
                        alert("<?php echo __('Please enter your name.'); ?>");
                        return false;
                    }
                    if (document.getElementById("contact_form_email").value === "") {
                        alert("<?php echo __('Please enter your email address.'); ?>");
                        return false;
                    }
                    if (document.getElementById("contact_form_message").value === "") {
                        alert("<?php echo __('Please enter your message.'); ?>");
                        return false;
                    }
                    <?php if (!empty($this->recaptcha_site_key) && !empty($this->recaptcha_secret_key)) : ?>
                        if (grecaptcha.getResponse() === "") {
                            alert("<?php echo __('Please verify that you are not a robot.'); ?>");
                            return false;
                        }
                    <?php endif; ?>
                    document.getElementById(contactFormId).submit();
                });
            });
        </script>
        <?php if (!empty($this->recaptcha_site_key) && !empty($this->recaptcha_secret_key)) : ?>
            <script>
                function onSubmit(token) {
                    document.getElementById("contactForm").submit();
                }
            </script>
        <?php endif;
    }

    /**
     * Verify reCAPTCHA
     * @return bool
     */
    private function verifyReCAPTCHA(): bool
    {
        if (empty($_POST['g-recaptcha-response'])) {
            return false;
        }

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
        $_POST['g-recaptcha-response'] = $captcha_success;
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
            self::OPTION_RECIPIENT_EMAILS,
            [$this, 'sanitize_email_addresses']
        );

        register_setting(
            'custom_contact_form_group',
            self::OPTION_RECAPTCHA_SITE_KEY
        );

        register_setting(
            'custom_contact_form_group',
            self::OPTION_RECAPTCHA_SECRET_KEY
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
            self::OPTION_RECIPIENT_EMAILS,
            __('Destination Email(s)'),
            [$this, 'email_field_callback'],
            'custom_contact_form_settings',
            'custom_contact_form_section'
        );

        // Add a field for the blacklist in the admin settings
        add_settings_field(
            self::OPTION_BLACKLISTED_COUNTRIES,
            __('Blacklisted Countries'),
            [$this, 'render_blacklist_field'],
            'custom_contact_form_settings',
            'custom_contact_form_section'
        );

        add_settings_field(
            self::OPTION_RECAPTCHA_SITE_KEY,
            'reCAPTCHA Site Key',
            [$this, 'recaptcha_site_key_callback'],
            'custom_contact_form_settings',
            'custom_contact_form_recaptcha_section'
        );

        add_settings_field(
            self::OPTION_RECAPTCHA_SECRET_KEY,
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
        $value = get_option(self::OPTION_RECIPIENT_EMAILS);
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
                    self::OPTION_RECIPIENT_EMAILS,
                    'invalid-email',
                    sprintf(__('Invalid email address') . ': %s', esc_html($email)),
                    'error'
                );
            }
        }

        if (empty($valid_emails)) {
            add_settings_error(
                self::OPTION_RECIPIENT_EMAILS,
                'invalid-email',
                __('Please enter at least one valid email address.'),
                'error'
            );
            return get_option(self::OPTION_RECIPIENT_EMAILS); // Revert to the previous value
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
        $blacklist = get_option(self::OPTION_BLACKLISTED_COUNTRIES, implode(',', $this->DefaultBlacklistedCountries));
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
        register_setting('custom_contact_form_group', self::OPTION_BLACKLISTED_COUNTRIES);
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
        $site_key = get_option(self::OPTION_RECAPTCHA_SITE_KEY, '');
        echo '<input type="text" id=' . self::OPTION_RECAPTCHA_SITE_KEY . ' name="' . self::OPTION_RECAPTCHA_SITE_KEY . '" value="' . esc_attr($site_key) . '" />';
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
        $secret_key = get_option(self::OPTION_RECAPTCHA_SECRET_KEY, '');
        echo '<input type="text" id="' . self::OPTION_RECAPTCHA_SECRET_KEY . '" name="' . self::OPTION_RECAPTCHA_SECRET_KEY . '" value="' . esc_attr($secret_key) . '" />';
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
        echo __('Configure reCAPTCHA settings for your form. Get your keys at') . ' <a href="https://www.google.com/recaptcha/admin">https://www.google.com/recaptcha/admin</a>.';
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
            self::OPTION_CUSTOM_CSS,
            [$this, 'sanitize_custom_css']
        );

        add_settings_section(
            'custom_contact_form_css_section',
            __('Custom CSS'),
            [$this, 'css_section_callback'],
            'custom_contact_form_settings'
        );

        add_settings_field(
            self::OPTION_CUSTOM_CSS,
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
        $custom_css = get_option(self::OPTION_CUSTOM_CSS, file_get_contents(__DIR__ . '/css/custom-contact-form.css'));

        // Display the textarea with the custom CSS
        echo '<textarea name="' . self::OPTION_CUSTOM_CSS . '" rows="8" cols="50">' . esc_textarea($custom_css) . '</textarea>';
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
        if (isset($_POST[self::OPTION_CUSTOM_CSS])) {
            $customCss = sanitize_text_field($_POST[self::OPTION_CUSTOM_CSS]);
            update_option(self::OPTION_CUSTOM_CSS, $customCss);
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
            // Look if the ip is banned
            $ip = $_SERVER['REMOTE_ADDR'];
            if ($this->is_ip_banned($ip)) {
                $this->display_error_message(__('Unauthorized submission'));
                return false;
            }

            // Check if the message is in banned_ips table
            $result = $this->query("SELECT * FROM ".$this->wpdb->prefix . self::BANNED_IPS_TABLE_NAME." WHERE `message` = '" . esc_sql($_POST['contact_form_message']) . "'");
            if (!empty($result)) {
                $this->display_error_message(__('Unauthorized submission'));
                $this->ban_ip($ip);
                return false;
            }

            // Check if the email is in banned_ips table
            $result = $this->query("SELECT * FROM ".$this->wpdb->prefix . self::BANNED_IPS_TABLE_NAME." WHERE `email` = '" . esc_sql($_POST['contact_form_email']) . "'");
            if (!empty($result)) {
                $this->display_error_message(__('Unauthorized submission'));
                $this->ban_ip($ip);
                return false;
            }

            //Get blacklisted country codes
            $blacklist = explode(',', get_option(self::OPTION_BLACKLISTED_COUNTRIES, implode(',', $this->DefaultBlacklistedCountries)));

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
                if (is_object($value)) {
                    $value = '<pre>' . print_r((array) $value, true) . '</pre>';
                }
                $message .= '<strong>' . $key . '</strong>: ' . $value . '<br/>';
            }

            $subject = sprintf('[%s] ' . __('Contact Form Submission from') . ' %s', $_SERVER['HTTP_HOST'], $name);
            $headers = sprintf('From: %s <%s>', $name, $email);

            // Check if the data is not empty
            if (!empty($name) && !empty($email) && !empty($message)) {
                apply_filters('wp_mail_content_type', 'text/html');

                // Get the recipient email address
                $to = get_option(self::OPTION_RECIPIENT_EMAILS);
                if (empty($to)) {
                    $this->display_error_message(__('No recipient email!'));
                    return false;
                }
                $result = wp_mail(explode(',', $to), $subject, $message, $headers);

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
            isset($_SERVER['HTTP_USER_AGENT']) &&
            !isset($_GET['spam']) &&
            wp_verify_nonce($_POST['contact_form_nonce'], 'contact') &&
            $this->is_same_origin_submission() &&
            isset($_POST['contact_form_token']) &&
            $_POST['contact_form_token'] === $_SESSION['contact_form_token'] &&
            !$this->is_proxy()
        ) {
            return true;
        }

        // If the form submission is invalid, ban the ip address of that client
        $ip = $_SERVER['REMOTE_ADDR'];
        $this->ban_ip($ip);

        return false;
    }

    /**
     * Ban an IP address.
     *
     * This method adds the specified IP address to the .htaccess file to prevent it from accessing the site.
     *
     * @param string $ip The IP address to ban.
     *
     * @since 1.3.3
     */
    private function ban_ip(string $ip): void
    {
        // if the server is apache
        if (strpos($_SERVER['SERVER_SOFTWARE'], 'Apache') !== false) {
            $htaccess = ABSPATH . '.htaccess';

            if (!file_exists($htaccess)) {
                // Create the .htaccess file if it doesn't exist
                touch($htaccess);
            }

            // Check if the .htaccess file exists
            if (file_exists($htaccess)) {
                // Check if the IP address is not already banned
                if (strpos(file_get_contents($htaccess), $ip) === false) {
                    // Add the IP address to the .htaccess file
                    file_put_contents($htaccess, PHP_EOL . 'deny from ' . $ip, FILE_APPEND);
                }
            }
        }

        // store banned ip in the database table banned_ips
        $geolocation = $this->getCountryFromIP($ip);
        $table_name = $this->wpdb->prefix . 'banned_ips';
        $this->wpdb->insert(
            $table_name,
            array(
                'ip' => $ip,
                'country_code' => $geolocation['country_code'],
                'country_name' => $geolocation['country_name'],
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                'city' => $geolocation['city'],
                'email' => $_POST['contact_form_email'] ?? 'unknown',
                'message' => $_POST['contact_form_message'] ?? 'unknown',
                'date' => current_time('mysql')
            )
        );
    }

    /**
     * Check if the IP address is banned. Look in db if ip exists in the table banned_ips. 
     * @param string $ip
     * @return bool
     */
    private function is_ip_banned(string $ip): bool
    {
        $result = $this->query("SELECT * FROM ".$this->wpdb->prefix . self::BANNED_IPS_TABLE_NAME." WHERE ip = %s",$ip);
        return !empty($result);
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
