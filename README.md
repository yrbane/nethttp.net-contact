# Custom Contact Form Plugin for WordPress

<!-- Ce badge affiche le nombre de téléchargements totaux du plugin nethttp.net-contact pour WordPress. Il peut être utile pour montrer la popularité du plugin. -->
![WordPress](https://img.shields.io/wordpress/plugin/dt/nethttp.net-contact)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-blue)

A custom contact form plugin for WordPress that allows you to easily create and manage contact forms on your website. 

## Features

- Easily create and manage contact forms.
- Automatically blocks submissions from blacklisted countries.
- Secure form submissions to prevent spam.
- If submissions are not valid, ips are banned and cannot resubmit contact form.
- Ips who are sending from same email or sending same message as another banned ip are also banned.
- Supports multiple recipient email addresses.
- Localisation.
- Custom css.
- Support for Google captcha reCAPTCHA.

## Todo

- Customize form fields and labels.
- Manage banned Ip
- ???

## Installation

1. Download the plugin ZIP file from the [latest release](https://github.com/yrbane/nethttp.net-contact/releases/latest).
2. Upload and activate the plugin through the WordPress admin panel.

## Usage

1. Once the plugin is activated, you can use the `[custom_contact_form]` shortcode to embed a contact form on your posts or pages.
2. Configure the plugin settings by going to the "Contact Form" section in the WordPress admin menu.

## Configuration

- **Destination Email(s):** Enter the email address(es) where contact form submissions should be sent. Separate multiple addresses with commas.
- **Blacklisted Countries:** Enter a comma-separated list of country codes to block submissions from those countries.
- **reCAPTCHA Settings:** Enter site key and secret key generated at [Google reCAPTCHA](https://www.google.com/recaptcha/admin).
- **Custom CSS:** Enter your custom CSS.

## License

This plugin is licensed under the [GNU General Public License v3.0](LICENSE.md).

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and updates to the plugin.

## Contributing

Contributions are welcome! If you find a bug or have an idea for a new feature, please open an issue or create a pull request.

## Author

- Name: @yrbane
- Email: <yrbane@nethttp.net>

## Support

For support and inquiries, please contact the author at the provided email address.

## Acknowledgments

- This is my first Wordpress extension.
- Special thanks to the WordPress community for their support and inspiration.

