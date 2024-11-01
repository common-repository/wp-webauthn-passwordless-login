<?php

    function mowebauthn_login_user_with2FA($Authenticator_userID)
    {
        $user_id = $Authenticator_userID;
        $currentuser = get_user_by('id',$user_id); 
        wp_set_current_user( $user_id, $currentuser->user_login );
        
        if (wp_validate_auth_cookie()==FALSE)
        {
            wp_set_auth_cookie($user_id, true);
            return true;
        }
        else
        {
            return false;
        }
    }
    function mowebauthn_runfile_e()
    {    

        require_once dirname(__FILE__).DIRECTORY_SEPARATOR.'WebAuthn.php';
        global $MowebAuthnDBQueries;
        global $current_user;
        $session_id_encrypt = false;
        
        if(isset($_POST['mo2f_parameter']))
        {
            $mo2f_parameter = explode('&', $_POST['mo2f_parameter']);
            array_shift($mo2f_parameter);
            $_GET['fn'] = sanitize_text_field($_POST['processName']);
            foreach ($mo2f_parameter as $key) {
                $key = explode('=', $key);
                $_GET[$key[0]] = sanitize_text_field($key[1]);
            }

        }
        if(isset($_POST['session_id_encrypt']))
        {
            $session_id_encrypt = sanitize_text_field($_POST['session_id_encrypt']);
        }
        if(isset($_GET['requireResidentKey']))
        {
            try {
            if(session_status() == PHP_SESSION_NONE) {
                
                session_start();
                
            }

            $fn = filter_input(INPUT_GET, 'fn');

            
            $requireResidentKey = !sanitize_text_field($_GET['requireResidentKey']);
            $userVerification = filter_input(INPUT_GET, 'userVerification', FILTER_SANITIZE_SPECIAL_CHARS);
            
            
            $post = trim(file_get_contents('php://input'));
            
            if(isset($_POST['mo2f_parameter']))
            {
                $fn = sanitize_text_field($_POST['processName']);
                $userVerification = sanitize_text_field($_GET['userVerification']);
            }

            if(isset($_POST['post']))
            {
                $post = $_POST['post']; 
                $post = str_replace('\\"', '"', $post);
              
            }
            
            if ($post) {
                $post = json_decode($post);
            }
            

            $formats = array();
            if (sanitize_text_field($_GET['fmt_android-key'])) {
                $formats[] = 'android-key';
            }
            if (sanitize_text_field($_GET['fmt_android-safetynet'])) {
                $formats[] = 'android-safetynet';
            }
            if (sanitize_text_field($_GET['fmt_apple'])) {
                $formats[] = 'apple';
            }
            if (sanitize_text_field($_GET['fmt_fido-u2f'])) {
                $formats[] = 'fido-u2f';
            }
            if (sanitize_text_field($_GET['fmt_none'])) {
                $formats[] = 'none';
            }
            if (sanitize_text_field($_GET['fmt_packed'])) {
                $formats[] = 'packed';
            }
            if (sanitize_text_field($_GET['fmt_tpm'])) {
                $formats[] = 'tpm';
            }

            $rpId = sanitize_text_field($_SERVER['HTTP_HOST']);            
            $typeUsb = !!sanitize_text_field($_GET['type_usb']);
            $typeNfc = !!sanitize_text_field($_GET['type_nfc']);
            $typeBle = !!sanitize_text_field($_GET['type_ble']);
            $typeInt = !!sanitize_text_field($_GET['type_int']);

            $crossPlatformAttachment = null;
            if (($typeUsb || $typeNfc || $typeBle) && !$typeInt) {
                $crossPlatformAttachment = true;

            } else if (!$typeUsb && !$typeNfc && !$typeBle && $typeInt) {
                $crossPlatformAttachment = false;
            }
            


            $WebAuthn = new \lbuchs\WebAuthn\moWebAuthn_WebAuthn('WebAuthn:'.$rpId, $rpId, $formats);

            if (sanitize_text_field($_GET['solo'])) {
                $WebAuthn->addRootCertificates('rootCertificates/solo.pem');
            }
            if (sanitize_text_field($_GET['apple'])) {
                $WebAuthn->addRootCertificates('rootCertificates/apple.pem');
            }
            if (sanitize_text_field($_GET['yubico'])) {
                $WebAuthn->addRootCertificates('rootCertificates/yubico.pem');
            }
            if (sanitize_text_field($_GET['hypersecu'])) {
                $WebAuthn->addRootCertificates('rootCertificates/hypersecu.pem');
            }
            if (sanitize_text_field($_GET['google'])) {
                $WebAuthn->addRootCertificates('rootCertificates/globalSign.pem');
                $WebAuthn->addRootCertificates('rootCertificates/googleHardware.pem');
            }
            if (sanitize_text_field($_GET['microsoft'])) {
                $WebAuthn->addRootCertificates('rootCertificates/microsoftTpmCollection.pem');
            }

            if(isset($_GET['session_id_encrypt']))
            	$session_id_encrypt = sanitize_text_field($_GET['session_id_encrypt']);
            
            if ($fn === 'getCreateArgs') {
                $username = $current_user->user_login;
                $userid = $current_user->ID;
                global $MowebAuthnDBQueries;
                $mowebauthn_ids = base64_decode($MowebAuthnDBQueries->get_user_detail('mowebauthn_credential_ID', $userid));
                $excludeCredentialIds = array();
                $createArgs = $WebAuthn->getCreateArgs($userid, $username, $username, 100, $requireResidentKey, $userVerification, $crossPlatformAttachment,$excludeCredentialIds);

                $_SESSION['challenge'] = $WebAuthn->getChallenge();      
                print(json_encode($createArgs));
                exit;

            } else if ($fn === 'getGetArgs') {
                $ids = array();
                    
                if(isset($_GET['session_id_encrypt']))
           		{  
                    $session_id_encrypt = sanitize_text_field($_GET['session_id_encrypt']);
                    $current_user_id = base64_decode(get_transient('mowebauthn_session_id'.$session_id_encrypt));
                        
                    $mowebauthn_ids = $MowebAuthnDBQueries->get_user_detail('mowebauthn_credential_ID', $current_user_id);
                    $mowebauthen_cred_ids = array(base64_decode($mowebauthn_ids));
                    if(!$mowebauthn_ids)
                    {
                        $current_user = get_user_by('id',$current_user_id);
                        wp_set_current_user( $current_user_id, $current_user->user_login );
                        wp_set_auth_cookie( $current_user_id, true );
                        $response = array('webauthn_init_success' => false);              
                        wp_send_json($response);
                    }
                    $getArgs = $WebAuthn->getGetArgs($mowebauthen_cred_ids, 20, $typeUsb, $typeNfc, $typeBle, $typeInt, $userVerification);
                    
                    $_SESSION['challenge'] = $WebAuthn->getChallenge();

                    print(json_encode($getArgs));
                    exit;
                }
               
                }

                else if ($fn === 'processCreate' && isset($post->clientDataJSON)) {
                $clientDataJSON = base64_decode($post->clientDataJSON);
                $attestationObject = base64_decode($post->attestationObject);
                $challenge = $_SESSION['challenge'];
                
                
                $data = $WebAuthn->processCreate($clientDataJSON, $attestationObject, $challenge, $userVerification === 'required');


                if (!array_key_exists('registrations', $_SESSION) || !is_array($_SESSION['registrations'])) {
                    $_SESSION['registrations'] = array();
                }
                $_SESSION['registrations'][] = $data;
 
                $return = new stdClass();
                $return->success = true;
                $return->msg = 'Registration Success';
                print(json_encode($return));

          
            } else if ($fn === 'processGet') {
                $clientDataJSON     = base64_decode($post->clientDataJSON);
                $authenticatorData  = base64_decode($post->authenticatorData);
                $mowebauthn_user_id = get_site_option(base64_decode($post->userhandle));
                $signature          = base64_decode($post->signature);
                $id                 = base64_decode($post->id);
                $challenge          = $_SESSION['challenge'];
                $mowebauthn_session_id = $session_id_encrypt;
                if($mowebauthn_session_id)
                {
                    $current_user_id = base64_decode(get_transient('mowebauthn_session_id'.$session_id_encrypt));
                    if($current_user_id != $mowebauthn_user_id)
                    {
                        $response = array('status' => 'FAILED',
                            'message' => 'User did not match.'
                        );
                        delete_transient('mowebauthn_session_id'.$session_id_encrypt);             
                        wp_send_json($response);
                    }        
                }
                $credentialPublicKey = base64_decode($MowebAuthnDBQueries->get_user_detail('mowebauthn_credentialPublicKey', $current_user_id));
               
                if ($credentialPublicKey === null) {
                    throw new Exception('Public Key for credential ID not found!');
                }

                $WebAuthn->processGet($clientDataJSON, $authenticatorData, $signature, $credentialPublicKey, $challenge, null, $userVerification === 'required');
                $response = '';
                if(mowebauthn_login_user_with2FA($mowebauthn_user_id))
                {
                    $response = array('status' => 'SUCCESS',
                        'message' => 'Successfully logged in.');              
                }   
                else 
                {
                    $response = array('status' => 'FAILED',
                        'message' => 'Unknown Error occured while validating user\'s identity.');              
                }   
                wp_send_json($response);
              
            } else if ($fn === 'clearRegistrations') {
                
                $_SESSION['registrations'] = null;
                $_SESSION['challenge'] = null;
                $return = new stdClass();
                $return->success = true;
                $return->msg = 'all registrations deleted';
                session_destroy();
                print(json_encode($return));
                exit;
            }

        } catch (Throwable $ex) {
            $return = new stdClass();
            $return->success = false;
            $return->msg = $ex->getMessage();
            print(json_encode($return));
        }

    }

}