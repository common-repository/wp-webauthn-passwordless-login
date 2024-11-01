jQuery(window).bind('load', function()
{	
	jQuery('form[name="loginform"]').prepend( "<div id='mo2f_msg' hidden class='message'></div>" );
	
    var moPreferredWebauthn = my_ajax_object.moPreferredWebauthn; 
	var mowebauthn_login = document.getElementById("wp-submit");
	var mowebauthn_password = document.getElementsByName('pwd')[0];
	var mowebauthn_name = document.getElementsByName('log')[0];
	mowebauthn_login.setAttribute('type', 'button');
    mowebauthn_login.setAttribute('id','mowebauthn_2fa_login');
	mowebauthn_login.setAttribute('name','mowebauthn_2fa_login');
	mowebauthn_password.setAttribute('id','mowebauthn_2fa_password');
	mowebauthn_password.setAttribute('name','mowebauthn_2fa_password');
	mowebauthn_name.setAttribute('id','mowebauthn_2fa_username');
	mowebauthn_name.setAttribute('name','mowebauthn_2fa_username');
	
	if(moPreferredWebauthn == "Passwordlesslogin"){
        var labeltags = document.getElementsByTagName("label");
        for (var i=0;i<labeltags.length;i++){
           if (labeltags[i].getAttribute("for")=="user_pass"){
               labeltags[i].remove();
           }
        }
        mowebauthn_password.setAttribute('hidden',true);
        var span = document.getElementsByClassName("dashicons-visibility")[0];
        span.setAttribute('hidden',true);
        jQuery(".dashicons-visibility").hide(); 
        jQuery(".dashicons").hide();

    }

    if(moPreferredWebauthn == "usernamelesslogin"){
        var labeltags = document.getElementsByTagName("label");
        for (var i=0;i<labeltags.length;i++){
           if (labeltags[i].getAttribute("for")=="user_pass"){
               labeltags[i].remove();
           }
        }
        for (var i=0;i<labeltags.length;i++){
           if (labeltags[i].getAttribute("for")=="user_login"){
               labeltags[i].remove();
           }
        }
        mowebauthn_password.setAttribute('hidden',true);
        mowebauthn_name.setAttribute('hidden',true); 
        var span = document.getElementsByClassName("dashicons-visibility");
        jQuery(".dashicons-visibility").hide(); 
        jQuery(".dashicons").hide();

    }

	jQuery('#mowebauthn_2fa_login').click(function(){
        mowebauthn_2fa_login();		
	});

	jQuery('#mowebauthn_2fa_password').keypress(function (e) {
		if (e.which == 13) {	
			e.preventDefault();
			mowebauthn_2fa_login();
		}
	});
    jQuery('#mowebauthn_2fa_username').keypress(function (e) {
        if (e.which == 13) {    
            e.preventDefault();
            mowebauthn_2fa_login();
        }
    });
	function mowebauthn_2fa_login()
	{
		jQuery("#mo2f_msg").empty();
        document.getElementById('mo2f_msg').setAttribute('hidden',true); 
		var data = {
			'action'                    : 'mowebauthn_ajax',
			'option' 					: 'mowebauthn_2fa_login',
			'username'					: jQuery('#mowebauthn_2fa_username').val(),
			'password'					: jQuery('#mowebauthn_2fa_password').val(),
			'nonce'						: my_ajax_object.nonce
		};
	
		jQuery.post(my_ajax_object.ajax_url, data, function(response) {
          
			if(response == 'incorrectUserNamePassword'){	
				jQuery("#mo2f_msg").empty();
                document.getElementById('mo2f_msg').setAttribute('hidden',false);
				jQuery("#mo2f_msg").append( 'Wrong username or password.' ).fadeIn();
			}
			else if ( typeof response.success !== 'undefined' && response.success == true) {
				 mowebauthn_checkregistration(response.mowebauthn_session_id);
            }
            else if ( response == 'InvalidRequest') {
            	jQuery("#mo2f_msg").empty();
                document.getElementById('mo2f_msg').setAttribute('hidden',false);
				jQuery("#mo2f_msg").append( 'Invalid Request' ).fadeIn();
			}
			});	
	}
	function mowebauthn_checkregistration(mowebauthn_session_id) {
		
        var site_url = my_ajax_object.site_url;
        var ajaxurl = site_url+'/'; 
        if (!window.fetch || !navigator.credentials || !navigator.credentials.create) {
            window.alert('Browser not supported.');
            return;
        }

        window.fetch(site_url+'?session_id_encrypt='+ mowebauthn_session_id +'&fn=getGetArgs' + mowebauthn_getGetParams(), {method:'GET',cache:'no-cache'}).then(function(response) {
            return response.json();

        }).then(function(json) {
            
            if(typeof json.webauthn_init_success !== 'undefined' && !json.webauthn_init_success)
            {
                location.href = site_url;
                throw new Error("logged in successfully");
            }
            
            if (json.success === false) {
                throw new Error(json.msg);
            }
            mowebauthn_recursiveBase64StrToArrayBuffer(json);
            return json;
            
        }).then(function(getCredentialArgs) {
            return navigator.credentials.get(getCredentialArgs);

        }).then(function(cred) {
            return {
                id: cred.rawId ? mowebauthn_arrayBufferToBase64(cred.rawId) : null,
                clientDataJSON: cred.response.clientDataJSON  ? mowebauthn_arrayBufferToBase64(cred.response.clientDataJSON) : null,
                authenticatorData: cred.response.authenticatorData ? mowebauthn_arrayBufferToBase64(cred.response.authenticatorData) : null,
                signature : cred.response.signature ? mowebauthn_arrayBufferToBase64(cred.response.signature) : null,
                userhandle : cred.response.userHandle ? mowebauthn_arrayBufferToBase64(cred.response.userHandle) : null 
            };

        }).then(JSON.stringify).then(function(AuthenticatorAttestationResponse) {
            let data =
            {
                'mowebauthn_action' : 'mo_two_factor_ajax',
                'mo_2f_two_factor_ajax' : 'yes',
                'mo2f_parameter' : mowebauthn_getGetParams(),
                'processName' : 'processGet',
                'session_id_encrypt' : mowebauthn_session_id,
                'post' : AuthenticatorAttestationResponse
            }
            $res = jQuery.post(ajaxurl,data,function (response) {
                return response;
            })
            return $res;
        }).then(function(response) {
            return response;

        }).then(function(json) {

            if (json.status == 'FAILED') {
            
            }
            else if(json.status == 'SUCCESS')
            {
                location.href = site_url;
            }
            else {
                throw new Error('An unknown Error has occured.');
            }
            jQuery("#mo2f_msg").empty();
            document.getElementById('mo2f_msg').setAttribute('hidden',false);
            jQuery("#mo2f_msg").append( json.message ).fadeIn();
        
        }).catch(function(err) {
            window.alert(err.message || 'unknown error occured');
        });
    }

    function mowebauthn_recursiveBase64StrToArrayBuffer(obj) {
        let prefix = '=?BINARY?B?';
        let suffix = '?=';
        if (typeof obj === 'object') {
            for (let key in obj) {
                if (typeof obj[key] === 'string') {
                    let str = obj[key];
                    if (str.substring(0, prefix.length) === prefix && str.substring(str.length - suffix.length) === suffix) {
                        str = str.substring(prefix.length, str.length - suffix.length);

                        let binary_string = window.atob(str);
                        let len = binary_string.length;
                        let bytes = new Uint8Array(len);
                        for (let i = 0; i < len; i++)        {
                            bytes[i] = binary_string.charCodeAt(i);
                        }
                        obj[key] = bytes.buffer;
                    }
                } else {
                    mowebauthn_recursiveBase64StrToArrayBuffer(obj[key]);
                }
            }
        }
    }
     function mowebauthn_arrayBufferToBase64(buffer) {
            let binary = '';
            let bytes = new Uint8Array(buffer);
            let len = bytes.byteLength;
            for (let i = 0; i < len; i++) {
                binary += String.fromCharCode( bytes[ i ] );
            }
            return window.btoa(binary);
        }

        /**
         * Get URL parameter
         * @returns {String}
         */
        function mowebauthn_getGetParams() {
            let url = '';
            url += '&page=miniOrange_2_factor_settings';
            url += '&apple=' + '1';
            url += '&yubico=' + '1';
            url += '&solo=' + '1';
            url += '&hypersecu=' +'1';
            url += '&google=' + '1';
            url += '&microsoft=' + '1';
            url += '&requireResidentKey=' + '1';
            url += '&type_usb=' + '1';
            url += '&type_nfc=' + '1';
            url += '&type_ble=' + '1';
            url += '&type_int=' + '1';

            url += '&fmt_android-key=' + '1';
            url += '&fmt_android-safetynet=' + '1';
            url += '&fmt_apple=' +'1';
            url += '&fmt_fido-u2f=' + '1';
            url += '&fmt_none=' + '1';
            url += '&fmt_packed=' + '1';
            url += '&fmt_tpm=' + '1';
            url += '&rpId=' + my_ajax_object.HTTP_HOST;
         
            url += '&userVerification=discouraged';
            return url;
        }

        /**
         * force https on load
         * @returns {undefined}
         */
        window.onload = function() {
            if (location.protocol !== 'https:' && !location.host.includes('localhost')) {
                location.href = location.href.replace('http', 'https');
            }
            if (!document.getElementById('rpId').value) {
                document.getElementById('rpId').value = location.hostname;
            }
        }


	
});

