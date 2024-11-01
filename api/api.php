<?php
class MOPPM_Api
{
    public static function wp_remote_post($url, $args = array())
    {
        $response = wp_remote_post($url, $args);
        if (!is_wp_error($response)) {

            return $response['body'];
        } else {
            $message = 'Please enable curl extension. <a href="admin.php?page=mo_2fa_troubleshooting">Click here</a> for the steps to enable curl.';

            return json_encode(array( "status" => 'ERROR', "message" => $message ));
        }
    }
    public static function make_curl_call($url, $fields, $http_header_array = array("Content-Type"=>"application/json","charset"=>"UTF-8","Authorization"=>"Basic"))
    {
        if (gettype($fields) !== 'string') {
            $fields = json_encode($fields);
        }

        $args = array(
            'method' => 'POST',
            'body' => $fields,
            'timeout' => '5',
            'redirection' => '5',
            'httpversion' => '1.0',
            'blocking' => true,
            'headers' => $http_header_array
        );

    
        $response = self::wp_remote_post($url, $args);

        return $response;
    }
    public static function get_customer_key($email, $password)
    {
        $url    = "https://login.xecurify.com/moas/rest/customer/key";
        $fields = array (
                    'email'     => $email,
                    'password'  => $password
                );
        $json       = json_encode($fields);
        $response   = self::make_curl_call($url, $json);
        return $response;
    }
    public static  function moppm_is_curl_installed()
    {
        if  (in_array ('curl', get_loaded_extensions()))
            return 1;
        else 
            return 0;
    }
public static function forgot_password()
    {
        $url    = MOPPM_Constants::HOST_NAME. '/moas/rest/customer/password-reset';
        $email = get_site_option('email');
        $key   = get_site_option('moppm_customerKey');
        $api   = get_site_option('moppm_api_key');
        $token = get_site_option('customer_token');
    
        $fields      = array(
         'email' => $email
                     );
        $json          = wp_json_encode($fields);
        $authHeader  = self ::createAuthHeader($key, $api);
        $response = self::make_curl_call($url, $json, $authHeader);
        return $response;
    }

public static function check_customer($email)
    {
        $url    = MOPPM_Constants::HOST_NAME . "/moas/rest/customer/check-if-exists";
        $fields = array(
                    'email'     => $email,
                );
        $json     = json_encode($fields);
        $response = self::make_curl_call($url, $json);
        return $response;
    }

    public static function create_customer($email, $company, $password, $phone = '', $first_name = '', $last_name = '')
    {
        $url = MOPPM_Constants::HOST_NAME . '/moas/rest/customer/add';
        $fields = array (
            'companyName'    => $company,
            'areaOfInterest' => 'WordPress Password Policy Plugin',
            'firstname'      => $first_name,
            'lastname'       => $last_name,
            'email'          => $email,
            'phone'          => $phone,
            'password'       => $password
        );
        $json = json_encode($fields);
        $response = self::make_curl_call($url, $json);
        return $response;
    }
public static function submit_contact_us($q_email, $q_phone, $query)
    {
        $current_user = wp_get_current_user();
        $url          = "https://login.xecurify.com/moas/rest/customer/contact-us";
        global $mowafutility;
        $query = '[miniOrange webauthn passwordless | Setting -V '.WORDPRESS_WEBAUTHN_PASSWORDLESS_LOGIN_VERSION.']: ' . $query;
        
        $fields = array(
                    'firstName' => $current_user->user_firstname,
                    'lastName'  => $current_user->user_lastname,
                    'company'   => $_SERVER['SERVER_NAME'],
                    'email'     => $q_email,
                    'ccEmail'   => '2fasupport@xecurify.com',
                    'phone'     => $q_phone,
                    'query'     => $query
                );
        $field_string = json_encode($fields);
        $response = self::make_curl_call($url, $field_string);
        return $response;
    }

public static function send_email_alert($email, $message, $feedback_option)
    {
        $phone      = get_option("admin_phone");
        $user       = wp_get_current_user();
        $activation_date    =  get_site_option('mowebautn_activated_time'); 
        $diff               = $activation_date - time();
        $days       = (!$activation_date)?'NA':intval(abs(round($diff / 86400)));
        $onprem     = WORDPRESS_WEBAUTHN_PASSWORDLESS_LOGIN_VERSION ? 'O':'C';
        if ($feedback_option == 'moppm_feedback') {
             $subject    = "Feedback: miniOrange Webauthn passwordless plugin - [".WORDPRESS_WEBAUTHN_PASSWORDLESS_LOGIN_VERSION.'] : [' .$days.']';
        }
        else
            $subject    = "[Deactivated feedback skipped]: miniOrange Webauthn passwordless plugin - [".WORDPRESS_WEBAUTHN_PASSWORDLESS_LOGIN_VERSION.'] : [' .$days.']';

        $query      = '[WordPress Webauthn passwordless Plugin: ' .$onprem. ' - V '.WORDPRESS_WEBAUTHN_PASSWORDLESS_LOGIN_VERSION.' ]: Feedback  :  ' . $message;

        $content    ='<div >Hello, <br><br>First Name :'.$user->user_nicename.'<br><br>Last  Name :'.$user->user_lastname.'   <br><br>Company :<a href="'.$_SERVER['SERVER_NAME'].'" target="_blank" >'.$_SERVER['SERVER_NAME'].'</a><br><br>Phone Number :'.$phone.'<br><br>Email :<a href="mailto:'.$email.'" target="_blank">'.$email.'</a><br><br>Query :'.$query.'</div>';

        $headers    = array('Content-Type: text/html; charset=UTF-8');

        $result     = wp_mail('2fasupport@xecurify.com',$subject,$content,$headers);

        return $result;

    }

public static function createAuthHeader($customerKey, $apiKey)
    {
        $currentTimestampInMillis = round(microtime(true) * 1000);
        $currentTimestampInMillis = number_format($currentTimestampInMillis, 0, '', '');
        $stringToHash   = $customerKey . $currentTimestampInMillis . $apiKey;
        ;
        $hashValue      = hash("sha512", $stringToHash);

        $headers = array(
            "Content-Type"  => "application/json",
            "Customer-Key"  => $customerKey,
            "Timestamp"     => $currentTimestampInMillis,
            "Authorization" => $hashValue
        );

        return $headers;
    }
}
