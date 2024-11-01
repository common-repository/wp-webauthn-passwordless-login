<?php

/**
 * Fired during plugin activation
 *
 * @link       www.miniorange.com
 * @since      1.0.0
 *
 * @package    Wordpress_Webauthn_Passwordless_Login
 * @subpackage Wordpress_Webauthn_Passwordless_Login/includes
 */

/**
 * Fired during plugin activation.
 *
 * This class defines all code necessary to run during the plugin's activation.
 *
 * @since      1.0.0
 * @package    Wordpress_Webauthn_Passwordless_Login
 * @subpackage Wordpress_Webauthn_Passwordless_Login/includes
 * @author     miniOrange <info@xecurify.com>
 */
class moWebauthn_Passwordless_Login_Activator {

	/**
	 * Short Description. (use period)
	 *
	 * Long Description.
	 *
	 * @since    1.0.0
	 */
	public static function activate() {
         add_site_option('mowebautn_activated_time', time());
		global $MowebAuthnDBQueries;
		$MowebAuthnDBQueries->mowebauthn_plugin_activate();		
		add_site_option('mowebauthn_allow_authenticator_type','none');
        
	}

}
