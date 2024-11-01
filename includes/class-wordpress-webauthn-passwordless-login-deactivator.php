<?php

/**
 * Fired during plugin deactivation
 *
 * @link       www.miniorange.com
 * @since      1.0.0
 *
 * @package    Wordpress_Webauthn_Passwordless_Login
 * @subpackage Wordpress_Webauthn_Passwordless_Login/includes
 */

/**
 * Fired during plugin deactivation.
 *
 * This class defines all code necessary to run during the plugin's deactivation.
 *
 * @since      1.0.0
 * @package    Wordpress_Webauthn_Passwordless_Login
 * @subpackage Wordpress_Webauthn_Passwordless_Login/includes
 * @author     miniOrange <info@xecurify.com>
 */
class moWebauthn_Passwordless_Login_Deactivator {

	/**
	 * Short Description. (use period)
	 *
	 * Long Description.
	 *
	 * @since    1.0.0
	 */
	public static function deactivate() {
        global $moppm_dirname;
      include $moppm_dirname .'wp-webauthn-passwordless-login'.DIRECTORY_SEPARATOR. 'views'.DIRECTORY_SEPARATOR.'feedback_form.php';
      //moweb_deactivate();

	}

}
