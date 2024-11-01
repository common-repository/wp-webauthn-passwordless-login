<?php

/**
 * Define the internationalization functionality
 *
 * Loads and defines the internationalization files for this plugin
 * so that it is ready for translation.
 *
 * @link       www.miniorange.com
 * @since      1.0.0
 *
 * @package    Wordpress_Webauthn_Passwordless_Login
 * @subpackage Wordpress_Webauthn_Passwordless_Login/includes
 */

/**
 * Define the internationalization functionality.
 *
 * Loads and defines the internationalization files for this plugin
 * so that it is ready for translation.
 *
 * @since      1.0.0
 * @package    Wordpress_Webauthn_Passwordless_Login
 * @subpackage Wordpress_Webauthn_Passwordless_Login/includes
 * @author     miniOrange <info@xecurify.com>
 */
class moWebauthn_Passwordless_Login_i18n {


	/**
	 * Load the plugin text domain for translation.
	 *
	 * @since    1.0.0
	 */
	public function load_plugin_textdomain() {

		load_plugin_textdomain(
			'wordpress-webauthn-passwordless-login',
			false,
			dirname( dirname( plugin_basename( __FILE__ ) ) ) . DIRECTORY_SEPARATOR.'languages'.DIRECTORY_SEPARATOR
		);

	}



}
