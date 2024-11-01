<?php
/**
 * 
 * 
 * @link              www.miniorange.com
 * @since             1.0.0
 * @package           Wordpress_Webauthn_Passwordless_Login
 *
 * @wordpress-plugin
 * Plugin Name:       webauthn-passwordless-login-wp
 * Plugin URI:        webauthn-passwordless-login-wp
 * Description:       This plugin allows you to login without using your device credentials like FACE ID, Finger Print, PIN. You can also enable passwordless and usernameless login for easy and secure access to your website.
 * Version:           1.5.1
 * Author:            miniOrange
 * Author URI:        www.miniorange.com
 * License:           GNUGPLv3
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       webauthn-passwordless-login-wp
 * Domain Path:       /languages
 */

global $moppm_dirname;
$moppm_dirname    = plugin_dir_path(dirname(__FILE__));
 define('MOPPM_TEST_MODE', false);

if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Currently plugin version.
 * Start at version 1.0.0 and use SemVer - https://semver.org
 * Rename this for your plugin and update it as you release new versions.
 */
define( 'WORDPRESS_WEBAUTHN_PASSWORDLESS_LOGIN_VERSION', '1.5.1' );
define('HOST_NAME', 'https://login.xecurify.com');

require_once( ABSPATH . 'wp-admin/includes/plugin.php' );


/**
 * The code that runs during plugin activation.
 * This action is documented in includes/class-wordpress-webauthn-passwordless-login-activator.php
 */
function activate_wordpress_webauthn_passwordless_login() {
	require_once plugin_dir_path( __FILE__ ) . 'includes'.DIRECTORY_SEPARATOR.'class-wordpress-webauthn-passwordless-login-activator.php';
	moWebauthn_Passwordless_Login_Activator::activate();
}

/**
 * The code that runs during plugin deactivation.
 * This action is documented in includes/class-wordpress-webauthn-passwordless-login-deactivator.php
 */
function deactivate_wordpress_webauthn_passwordless_login() {
	require_once plugin_dir_path( __FILE__ ) . 'includes'.DIRECTORY_SEPARATOR.'class-wordpress-webauthn-passwordless-login-deactivator.php';
	moWebauthn_Passwordless_Login_Deactivator::deactivate();
}

register_activation_hook( __FILE__, 'activate_wordpress_webauthn_passwordless_login' );
register_deactivation_hook( __FILE__, 'deactivate_wordpress_webauthn_passwordless_login' );

add_action('admin_menu','mowebauthn_auth_menu');
add_action('init','mowebauthn_init');
add_action('login_form','mowebauthn_script_load' );
add_action('wp_ajax_nopriv_mowebauthn_ajax','mowebauthn_ajax');
add_action('admin_footer', 'mowebauthn_feedback_request' );
function mowebauthn_feedback_request(){
	 if ('plugins.php' != basename($_SERVER['PHP_SELF'])) {
            return;
        }
        global $moppm_dirname;

        $email = get_site_option("email");
        if (empty($email)) {
            $user = wp_get_current_user();
            $email = $user->user_email;
        }
        $imagepath=plugins_url('/includes/images/', __FILE__);
        wp_enqueue_style('wp-pointer');
        wp_enqueue_script('wp-pointer');
        wp_enqueue_script('utils');
        wp_enqueue_style('moppm_admin_plugins_page_style', plugins_url('/includes/css/moppm_feedback_style.css?ver=4.8.60', __FILE__));
        include $moppm_dirname.'wp-webauthn-passwordless-login'.DIRECTORY_SEPARATOR . 'views'.DIRECTORY_SEPARATOR.'feedback_form.php';

}


function mowebauthn_get_session_id($length = 10)
{
	$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $mowebauth_session_id = '';
    for ($i = 0; $i < $length; $i++) {
        $mowebauth_session_id .= $characters[rand(0, $charactersLength - 1)];
    }
    return $mowebauth_session_id;
}

function mowebauthn_ajax()
{
	if(isset($_POST['option']) && sanitize_text_field($_POST['option']) == 'mowebauthn_2fa_login')
	{
		$nonce = isset($_POST['nonce']) ? sanitize_text_field($_POST['nonce']) : '';
		if ( ! wp_verify_nonce( $nonce, 'mowebauthn-2fa-login' ) ) {
			wp_send_json('InvalidRequest');
			wp_die();
		}
		$username = sanitize_text_field($_POST['username']);
		$password = $_POST['password'];
		$currentuser = wp_authenticate_username_password(null, $username, $password);
		if (is_wp_error($currentuser)) {
			wp_send_json('incorrectUserNamePassword');
			wp_die();
		}		
		set_transient('mowebauthn_credential_verification','success',600);
		$mowebauthn_session_id = mowebauthn_get_session_id(12);
		set_transient('mowebauthn_session_id'.$mowebauthn_session_id,base64_encode($currentuser->ID),600);
		$response = array('success' => true,
			'mowebauthn_session_id' => $mowebauthn_session_id,
		);				
		wp_send_json($response);
	}
}
					
function mowebauthn_script_load()
{
	$site_url = get_site_option("siteurl");
	if(!strpos($site_url, 'localhost'))
	{
		$site_url = str_replace('http://', 'https://', $site_url);
	}
	$moPreferredWebauthn = get_site_option("moPreferredWebauthn");
	wp_enqueue_script('jquery');
	wp_enqueue_script( 'mowebauthn_ajax_login_default', plugins_url( 'public/js/two_factor_webauthn.js', __FILE__));
    wp_localize_script( 'mowebauthn_ajax_login_default', 'my_ajax_object', array( 'ajax_url' => admin_url( 'admin-ajax.php' ) ,
    	'nonce' => wp_create_nonce("mowebauthn-2fa-login"),
    	'site_url' => $site_url,
    	'moPreferredWebauthn' => $moPreferredWebauthn,
    	'HTTP_HOST' => $_SERVER['HTTP_HOST']
    ) );
		
}
function mowebauthn_auth_menu() {
	
	$iconurl = plugin_dir_url(__FILE__) . 'public'.DIRECTORY_SEPARATOR.'images'.DIRECTORY_SEPARATOR.'miniorange_icon.png';

	if(current_user_can( 'manage_options' ) ){
		$mo2fa_hook_page = add_menu_page ('WebAuthn Passwordless login',  'WebAuthn Passwordless login', 'administrator', 'miniOrange_webauthn_settings', 'mowebauthn_login_options',$iconurl);
	}
}
function mowebauthn_network_auth_network_menu(){
	
	$iconurl = plugin_dir_url(__FILE__) . DIRECTORY_SEPARATOR.'public'.DIRECTORY_SEPARATOR.'images'.DIRECTORY_SEPARATOR.'miniorange_icon.png';
	
	if(current_user_can( 'manage_options' )&& is_super_admin()){
		$mo2fa_hook_page = add_menu_page ('webAuthn Passwordless login',  'webAuthn Passwordless login', 'manage_options', 'miniOrange_webauthn_settings', 'mowebauthn_login_options',$iconurl);
	}
}

 function mowebauthn_login_options()
{

	$mowebauthn_active_tab = isset($_GET['mowebauthn_tab']) ? sanitize_text_field($_GET['mowebauthn_tab']) : 'mowebauthn_setting';

	?>
	<div id="tab">
		<h2 class="nav-tab-wrapper">
		
			<a href="admin.php?page=miniOrange_webauthn_settings&amp;mowebauthn_tab=mowebauthn_setting" class="nav-tab <?php echo $mowebauthn_active_tab == 'mowebauthn_setting' ? 'nav-tab-active' : ''; ?>" id="mowebauthn_settings"><?php echo __('Settings','miniorange-web-authentication');?></a>

			<a href="admin.php?page=miniOrange_webauthn_settings&amp;mowebauthn_tab=mowebauthn_configure" class="nav-tab <?php echo $mowebauthn_active_tab == 'mowebauthn_configure' ? 'nav-tab-active' : ''; ?>" id="mowebauthn_configure"><?php echo __('Configure Webauthn','miniorange-web-authentication');?></a>
						
			<a href="admin.php?page=miniOrange_webauthn_settings&amp;mowebauthn_tab=mowebauthn_premium_option" class="nav-tab <?php echo $mowebauthn_active_tab == 'mowebauthn_premium_option' ? 'nav-tab-active' : ''; ?>" id="mowebauthn_premium_option"><?php echo __('Premium Options','miniorange-web-authentication');?></a>
			  
			
		</h2>
		</div>
	<?php
	if($mowebauthn_active_tab=='mowebauthn_setting')
	{
		echo '<table style="width:100%;padding:10px;">
		<tbody>
		<tr><td style="width:70%;vertical-align:top;">
		';
		require plugin_dir_path( __FILE__ ) . 'views'.DIRECTORY_SEPARATOR.'mowebauthn_settings.php';
		echo '</td>
		<td style="vertical-align:top;padding-left:1%;" id = "mowebauthn_support_table">	
		';
		require plugin_dir_path( __FILE__ ) . 'views'.DIRECTORY_SEPARATOR.'mowebauthn_support_form.php';
		echo '</td></tr></tbody>
		</table>';
	}
	else if($mowebauthn_active_tab=='mowebauthn_configure')
	{
		echo '<table style="width:100%;padding:10px;">
		<tbody>
		<tr><td style="width:70%;vertical-align:top;">
		';
		require plugin_dir_path( __FILE__ ) . 'views'.DIRECTORY_SEPARATOR.'mowebauthn_configure.php';
		echo '</td>
		<td style="vertical-align:top;padding-left:1%;" id = "mowebauthn_support_table">	
		';
		require plugin_dir_path( __FILE__ ) . 'views'.DIRECTORY_SEPARATOR.'mowebauthn_support_form.php';
		echo '</td></tr></tbody>
		</table>';
	}
	else if($mowebauthn_active_tab=='mowebauthn_premium_option')
	{
		echo '<table style="width:100%;padding:10px;">
		<tbody>
		<tr><td style="width:70%;vertical-align:top;">
		';
		require plugin_dir_path( __FILE__ ) . 'views'.DIRECTORY_SEPARATOR.'mowebauthn_premium_option.php';
		echo '</td>
		<td style="vertical-align:top;padding-left:1%;" id = "mowebauthn_support_table">	
		';
		require plugin_dir_path( __FILE__ ) . 'views'.DIRECTORY_SEPARATOR.'mowebauthn_support_form.php';
		echo '</td></tr></tbody>
		</table>';

	}
}

function mowebauthn_init()
{
   

	if(isset($_GET['fn']) or (isset($_POST['mowebauthn_action']) and sanitize_text_field($_POST['mowebauthn_action']) != 'login_customer') )
	{	
		include_once dirname( __FILE__ ).DIRECTORY_SEPARATOR.'webauthn'.DIRECTORY_SEPARATOR.'mo2f_initiate_webauthn.php';
		mowebauthn_runfile_e();
		exit;
	}
	
	if (current_user_can('manage_options')  && isset($_POST['mowebauthn_send_query'])) {
    $option = sanitize_text_field($_POST['mowebauthn_send_query']);
    switch ($option) {
        case "Submit Query":
            mowebauthn_handle_support_form(sanitize_email($_POST['mowebauthn_query_email']), sanitize_text_field($_POST['mowebauthn_query']), sanitize_text_field($_POST['query_phone']));
            break;
    }
}
if (current_user_can('manage_options')  && isset($_POST['option'])) {
    $option = sanitize_text_field($_POST['option']);
    switch ($option) {
        case "moppm_feedback":
        case "moppm_skip_feedback":
            mowebauthn_handle_feedback_form($_POST);
            break;
    }}
}

function mowebauthn_handle_feedback_form($postdata){
        
    require('api'.DIRECTORY_SEPARATOR.'api.php');

    if (MOPPM_TEST_MODE) {
        deactivate_plugins( plugin_basename( __FILE__ ), true );     
    }
   

    $nonce = sanitize_text_field($_POST['_wpnonce']);
    if (!wp_verify_nonce($nonce,'moppm_feedback')) {
        do_action('moppm_show_message', MOPPM_Messages::showMessage('ERROR'), 'ERROR');
        return;
    }
  
    $email = $_POST['query_mail'];
    $feedback_option = $_POST['option'];
    $message = $_POST['moppm_query_feedback'];
    $feedback_reasons = new MOPPM_Api();
    $feedback_reasons->send_email_alert($email,  $message, $feedback_option);
    deactivate_plugins( plugin_basename( __FILE__ ), true );
            
}
function mowebauthn_handle_support_form($email, $query, $phone)
{
	require('api'.DIRECTORY_SEPARATOR.'api.php');

    if (empty($email) || empty($query)) {
        return;
    }
    $contact_us = new MOPPM_Api();
    $contact_us->submit_contact_us($email, $phone, $query);
    if (json_last_error() == JSON_ERROR_NONE) {
        return;
    }            
    do_action('moppm_show_message', MOPPM_Messages::showMessage('SUPPORT_FORM_ERROR'), 'ERROR');
    return;
	
}
/**
 * The core plugin class that is used to define internationalization,
 * admin-specific hooks, and public-facing site hooks.
 */
require plugin_dir_path( __FILE__ ) . 'includes'.DIRECTORY_SEPARATOR.'class-wordpress-webauthn-passwordless-login.php';



/**
 * Begins execution of the plugin.
 *
 * Since everything within the plugin is registered via hooks,
 * then kicking off the plugin from this point in the file does
 * not affect the page life cycle.
 *
 * @since    1.0.0
 */
function mowebauthn_passwordless_login() {

	$plugin = new moWebauthn_Passwordless_Login();
	$plugin->mo_webauthn_run();

}
mowebauthn_passwordless_login();
