<?php

function mowebauthn_configure_webauthn( $user ) {


    $site_url = get_site_option("siteurl");
    if(!strpos($site_url, 'localhost'))
    {
        $site_url = str_replace('http://', 'https://', $site_url);
    }
    

	?>
    <h3>
        <?php echo 'Configure Web Authentication'; ?> 
    </h3>
    <hr>

    <script>
        var site_url = '<?php echo $site_url;?>';
    
        

        var ajaxurl = site_url+'/';  
        /**
         * creates a new FIDO2 registration
         * @returns {undefined}
         */
        function mowebauthn_newregistration() {
            
            if (!window.fetch || !navigator.credentials || !navigator.credentials.create) {
                window.alert('Browser not supported.');
                return;
            }

            window.fetch(site_url+'?fn=getCreateArgs' + mowebauthn_getGetParams(), {method:'GET',cache:'no-cache'}).then(function(response) {
                
                return response.json();

            }).then(function(json) {
                if (json.success === false) {
                    throw new Error(json.msg);
                }
                mowebauthn_recursiveBase64StrToArrayBuffer(json);
                return json;

            }).then(function(createCredentialArgs) {

                return navigator.credentials.create(createCredentialArgs);

            }).then(function(cred) {
                return {
                    clientDataJSON: cred.response.clientDataJSON  ? mowebauthn_arrayBufferToBase64(cred.response.clientDataJSON) : null,
                    attestationObject: cred.response.attestationObject ? mowebauthn_arrayBufferToBase64(cred.response.attestationObject) : null
                };

            }).then(JSON.stringify).then(function(AuthenticatorAttestationResponse) {
                let data ={
                        'mowebauthn_action' : 'mo_two_factor_ajax',
                        'option' : 'mo2f_set_data_webauthn',
                        'mo2f_parameter' : mowebauthn_getGetParams(),
                        'processName' : 'processCreate',
                        'post' : AuthenticatorAttestationResponse
                }

                var res = jQuery.post(ajaxurl,data,function (response) {
                    return response;
                })
               return res;
            }).then(function(response) {
                return JSON.parse(response);
            }).then(function(json) {
                if (json.success) {
                    alert("Device Added successfully");
                } else {
                    throw new Error(json.msg);
                }
            }).catch(function(err) {
                window.alert(err.message || 'unknown error occured');
            });
        }


        /**
         * checks a FIDO2 registration
         * @returns {undefined}
         */
        function mowebauthn_checkregistration() {

            if (!window.fetch || !navigator.credentials || !navigator.credentials.create) {
                window.alert('Browser not supported.');
                return;
            }

            window.fetch(site_url+'?fn=getGetArgs' + mowebauthn_getGetParams(), {method:'GET',cache:'no-cache'}).then(function(response) {
                return response.json();

            }).then(function(json) {

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
                    signature : cred.response.signature ? mowebauthn_arrayBufferToBase64(cred.response.signature) : null
                };

            }).then(JSON.stringify).then(function(AuthenticatorAttestationResponse) {
                let data =
                    {
                        'mowebauthn_action' : 'mo_two_factor_ajax',
                        'mo_2f_two_factor_ajax' : 'yes',
                        'mo2f_parameter' : mowebauthn_getGetParams(),
                        'processName' : 'processGet',
                        'post' : AuthenticatorAttestationResponse
                    }
                jQuery.post(ajaxurl,data,function (response) {
                    return response;
                })

            }).then(function(response) {
                return response;

            }).then(function(json) {
                 if (json.success) {
                    alert('login success');
                } else {
                    throw new Error(json.msg);
                }

            }).catch(function(err) {
                window.alert(err.message || 'unknown error occured');
            });
        }

        function mowebauthn_clearregistration() {
            window.fetch(site_url+'?fn=clearRegistrations' + mowebauthn_getGetParams(), {method:'GET',cache:'no-cache'}).then(function(response) {
                return response.json();

            }).then(function(json) {
                if (json.success) {
                    window.alert(json.msg);
                } else {
                    throw new Error(json.msg);
                }
            }).catch(function(err) {
                window.alert(err.message || 'unknown error occured');
            });
        }

        /**
         * convert RFC 1342-like base64 strings to array buffer
         * @param {mixed} obj
         * @returns {undefined}
         */
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

        /**
         * Convert a ArrayBuffer to Base64
         * @param {ArrayBuffer} buffer
         * @returns {String}
         */
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
            url += '&apple=' + (document.getElementById('cert_apple').checked ? '1' : '0');
            url += '&yubico=' + (document.getElementById('cert_yubico').checked ? '1' : '0');
            url += '&solo=' + (document.getElementById('cert_solo').checked ? '1' : '0');
            url += '&hypersecu=' + (document.getElementById('cert_hypersecu').checked ? '1' : '0');
            url += '&google=' + (document.getElementById('cert_google').checked ? '1' : '0');
            url += '&microsoft=' + (document.getElementById('cert_microsoft').checked ? '1' : '0');
            url += '&requireResidentKey=' + (document.getElementById('requireResidentKey').checked ? '1' : '0');
            url += '&type_usb=' + (document.getElementById('type_usb').checked ? '1' : '0');
            url += '&type_nfc=' + (document.getElementById('type_nfc').checked ? '1' : '0');
            url += '&type_ble=' + (document.getElementById('type_ble').checked ? '1' : '0');
            url += '&type_int=' + (document.getElementById('type_int').checked ? '1' : '0');

            url += '&fmt_android-key=' + (document.getElementById('fmt_android-key').checked ? '1' : '0');
            url += '&fmt_android-safetynet=' + (document.getElementById('fmt_android-safetynet').checked ? '1' : '0');
            url += '&fmt_apple=' + (document.getElementById('fmt_apple').checked ? '1' : '0');
            url += '&fmt_fido-u2f=' + (document.getElementById('fmt_fido-u2f').checked ? '1' : '0');
            url += '&fmt_none=' + (document.getElementById('fmt_none').checked ? '1' : '0');
            url += '&fmt_packed=' + (document.getElementById('fmt_packed').checked ? '1' : '0');
            url += '&fmt_tpm=' + (document.getElementById('fmt_tpm').checked ? '1' : '0');
            url += '&rpId=' + '<?php echo $_SERVER["HTTP_HOST"]; ?>';

            if (document.getElementById('userVerification_required').checked) {
                url += '&userVerification=required';

            } else if (document.getElementById('userVerification_preferred').checked) {
                url += '&userVerification=preferred';

            } else if (document.getElementById('userVerification_discouraged').checked) {
                url += '&userVerification=discouraged';
            }
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

    </script>

    <div>
        <div>&nbsp;</div>
        <table>
            <tbody><tr>
                <td>
                    <button class="button button-primary button-large" type="button" onclick="mowebauthn_newregistration()"> Add a new device </button>
                </td>
             
            </tr>
            </tbody>
        </table>
        <div>&nbsp;</div>


        <div id="webAuthn" hidden>
            <div>
                <input type="checkbox" id="requireResidentKey" name="requireResidentKey">
                <label for="requireResidentKey">Use Client-side-resident Public Key Credential Source</label>
            </div>

            <div>&nbsp;</div>
            <div style="font-weight: bold">Relying Party</div>
            <p style="margin:0 0 5px 0;font-size:0.9em;font-style: italic;">A valid domain string that identifies the
                WebAuthn Relying Party<br/>on whose behalf a given registration or authentication ceremony is being performed.</p>
            <div>
                <label for="rpId">RP ID:</label>
                <input type="text" id="rpId" name="rpId" value="<?php echo $_SERVER['HTTP_HOST']; ?>">
            </div>

            <div>&nbsp;</div>
            <div style="font-weight: bold">attestation statement format</div>
            <div>
                <input type="checkbox" id="fmt_android-key" name="fmt_android-key" checked>
                <label for="fmt_android-key">android-key</label>
            </div>

            <div>
                <input type="checkbox" id="fmt_android-safetynet" name="fmt_android-safetynet" checked>
                <label for="fmt_android-safetynet">android-safetynet</label>
            </div>

            <div>
                <input type="checkbox" id="fmt_apple" name="fmt_apple" checked>
                <label for="fmt_apple">apple</label>
            </div>

            <div>
                <input type="checkbox" id="fmt_fido-u2f" name="fmt_fido-u2f" checked>
                <label for="fmt_fido-u2f">fido-u2f</label>
            </div>

            <div>
                <input type="checkbox" id="fmt_none" name="fmt_none" checked>
                <label for="fmt_none">none</label>
            </div>

            <div>
                <input type="checkbox" id="fmt_packed" name="fmt_packed" checked>
                <label for="fmt_packed">packed</label>
            </div>

            <div>
                <input type="checkbox" id="fmt_tpm" name="fmt_tpm" checked>
                <label for="fmt_tpm">tpm</label>
            </div>

            <div>&nbsp;</div>
            <div style="font-weight: bold">user verification</div>
            <div>
                <input type="radio" id="userVerification_required" name="userVerification">
                <label for="userVerification_required">required <i style="font-size: 0.8em;">User verification is required (e.g. by pin), the operation will fail if the response does not have the UV flag.</i></label>
            </div>

            <div>
                <input type="radio" id="userVerification_preferred" name="userVerification">
                <label for="userVerification_preferred">preferred <i style="font-size: 0.8em;">user verification is prefered, the operation will not fail if the response does not have the UV flag.</i></label>
            </div>

            <div>
                <input type="radio" id="userVerification_discouraged" name="userVerification" checked>
                <label for="userVerification_discouraged">discouraged <i style="font-size: 0.8em;">user verification should not be employed as to minimize the user interaction during the process.</i></label>
            </div>

            <div>&nbsp;</div>
            <div style="font-weight: bold">type of authenticator</div>
            <div>
                <input type="checkbox" id="type_usb" name="type_usb" checked>
                <label for="type_usb">USB</label>
            </div>
            <div>
                <input type="checkbox" id="type_nfc" name="type_nfc" checked>
                <label for="type_nfc">NFC</label>
            </div>
            <div>
                <input type="checkbox" id="type_ble" name="type_ble" checked>
                <label for="type_ble">BLE</label>
            </div>
            <div>
                <input type="checkbox" id="type_int" name="type_int" checked>
                <label for="type_int">internal <i style="font-size: 0.8em;">Windows Hello, Android SafetyNet, Apple, ...</i></label>
            </div>


            <div>&nbsp;</div>
            <div style="font-weight: bold">root certificates</div>

            <div>
                <input type="checkbox" id="cert_apple" name="apple" checked>
                <label for="cert_apple">Accept keys signed by apple root ca</label>
            </div>

            <div>
                <input type="checkbox" id="cert_yubico" name="yubico" checked>
                <label for="cert_yubico">Accept keys signed by yubico root ca</label>
            </div>

            <div>
                <input type="checkbox" id="cert_solo" name="solo" checked>
                <label for="cert_solo">Accept keys signed by solokeys root ca</label>
            </div>

            <div>
                <input type="checkbox" id="cert_hypersecu" name="hypersecu" checked>
                <label for="cert_hypersecu">Accept keys signed by hypersecu root ca</label>
            </div>

            <div>
                <input type="checkbox" id="cert_google" name="google" checked>
                <label for="cert_google">Accept keys signed by google root ca</label>
            </div>

            <div>
                <input type="checkbox" id="cert_microsoft" name="microsoft" checked>
                <label for="cert_microsoft">Accept keys signed by Microsofts collection of trusted TPM root ca</label>
            </div>
           
        </div>

    </div>


   
	<?php
}

?>