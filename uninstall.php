<?php

/**
 * Fired when the plugin is uninstalled.
 *
 * When populating this file, consider the following flow
 * of control:
 *
 * - This method should be static
 * - Check if the $_REQUEST content actually is the plugin name
 * - Run an admin referrer check to make sure it goes through authentication
 * - Verify the output of $_GET makes sense
 * - Repeat with other user roles. Best directly by using the links/query string parameters.
 * - Repeat things for multisite. Once for a single site in the network, once sitewide.
 *
 * This file may be updated more in future version of the Boilerplate; however, this is the
 * general skeleton and outline for how the file should work.
 *
 * For more information, see the following discussion:
 * 
 *
 * @link       www.miniorange.com
 * @since      1.0.0
 *
 * @package    Wordpress_Webauthn_Passwordless_Login
 */

// If uninstall not called from WordPress, then exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

include_once dirname( __FILE__ ) . '/database/database_functions.php';
global $wpdb;
$MowebAuthndbQueries = new MoWebAuthnDB();

if(is_multisite()){
	$table_name = $wpdb->base_prefix . 'mowebAuthn_user_details';
}else{
	$table_name = $wpdb->prefix . 'mowebAuthn_user_details';
}
$MowebAuthndbQueries->mowebauthn_drop_table( $table_name );

delete_site_option('moPreferredWebauthn');
delete_site_option('mowebauthn_allow_authenticator_type');
delete_site_option('mowebauthn_inline_registration');
delete_site_option('mowebauthn_device_limitation');
delete_site_option('mowebauthn_usernameless_login');

