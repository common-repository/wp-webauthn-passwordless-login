<?php 

if(isset($_POST))
{
	if(isset($_POST['_wpnonce']) && wp_verify_nonce(sanitize_text_field($_POST['_wpnonce']), 'mowebauthn-save-settings-nonce'))
	{
    	if(isset($_POST['moPreferredWebauthn']))
    	{
    		update_site_option('moPreferredWebauthn',sanitize_text_field($_POST['moPreferredWebauthn']));
    	}
    	if(isset($_POST['mowebauthn_allow_authenticator_type']))
    	{
    		update_site_option('mowebauthn_allow_authenticator_type',sanitize_text_field($_POST['mowebauthn_allow_authenticator_type']));
    	}
        if(isset($_POST['mowebauthn_inline_registration']))
        {
            update_site_option('mowebauthn_inline_registration',sanitize_text_field($_POST['mowebauthn_inline_registration']));
        }
 		
    }
}

if(current_user_can('administrator')){ ?>
<form method="post" action="">
<?php
wp_nonce_field('mowebauthn-save-settings-nonce');
?>
<table class="form-table" >
<tr>
<th scope="row" style="width:400px"><label><?php _e('Preferred way of WebAuthn', 'mowebauthn-passwordless-login');?></label></th>
<td><?php 

$moPreferredWebauthn=get_site_option('moPreferredWebauthn');?>
<select name="moPreferredWebauthn" id="moPreferredWebauthn">
    <option value="withPassword" <?php if($moPreferredWebauthn === 'withPassword'){?> selected<?php }?>><?php _e('webauthn as second factor', 'mowebauthn-passwordless-login');?></option>
  
    <option value="multipleMethodsOnlogin"<?php if($moPreferredWebauthn === 'multipleMethodsOnlogin'){?> selected<?php }?>><?php _e('Multiple methods on login', 'mowebauthn-passwordless-login');?></option>
    <option value="usernamelesslogin"<?php if($moPreferredWebauthn === 'usernamelesslogin'){?> selected<?php }?>><?php _e('Username less login', 'mowebauthn-passwordless-login');?></option>

</select>
<p class="description"><?php _e('In "webauthn as the second factor", you will verify webauthn after username and password verification <br><br>In "Multiple methods on login" You will get multiple option on login for webauthn. You can choose wether you want to login with webauthn or usual username+password.', 'mowebauthn-passwordless-login');?></p>
</td>
</tr>
    
<tr>

<th scope="row"><label for="mowebauthn_inline_registration"><?php _e('User Enrollement for webauthn', 'mowebauthn-passwordless-login');?></label></th>
<td>
    <?php
    $mowebauthn_inline_registration=get_site_option('mowebauthn_inline_registration');?>
    
    <select name="mowebauthn_inline_registration" id="mowebauthn_inline_registration">
        <option value="Inline" <?php if($mowebauthn_inline_registration === 'Inline'){?> selected<?php }?>><?php _e('Enable Inline Registration', 'mowebauthn-passwordless-login');?></option>
        <option value="Normal"<?php if($mowebauthn_inline_registration === 'Normal'){?> selected<?php }?>><?php _e('Disable Inline Registration', 'mowebauthn-passwordless-login');?></option>
    </select>
    <p class="description"><?php _e('Inline registation will allow your users to configure their device on first login. This is not applicable if you are using webauthn as passwordless authentication.');?></p>
</td>
</tr>
<tr>
<th scope="row"><label for="mowebauthn_device_limitation"><?php _e('Device Restriction<b style = "color:red"></b>', 'mowebauthn-passwordless-login');?></label></th>
<td>
    <?php
    $mowebauthn_device_limitation=get_site_option('mowebauthn_device_limitation');?>
    <select name="mowebauthn_device_limitation" disabled id="mowebauthn_device_limitation">
        <option value="1" <?php if($mowebauthn_device_limitation === '1'){?> selected<?php }?>><?php _e('1 (Default)', 'mowebauthn-passwordless-login');?></option>
        <option value="2"<?php if($mowebauthn_device_limitation === '2'){?> selected<?php }?>><?php _e('2', 'mowebauthn-passwordless-login');?></option>
        <option value="3" <?php if($mowebauthn_device_limitation === '3'){?> selected<?php }?>><?php _e('5', 'mowebauthn-passwordless-login');?></option>
        <option value="4"<?php if($mowebauthn_device_limitation === '4'){?> selected<?php }?>><?php _e('choose number', 'mowebauthn-passwordless-login');?></option>
    </select>
    
    <p class="description"><?php _e('You can limit the number of register devices per user.');?></p>
</td>
</tr>
<th scope="row"><label for="mowebauthn_allow_authenticator_type"><?php _e('Allow a specific type of authenticator', 'mowebauthn-passwordless-login');?></label></th>
<td>
<?php $mowebauthn_allow_authenticator_type=get_site_option('mowebauthn_allow_authenticator_type');
if($mowebauthn_allow_authenticator_type === false){
    update_site_option('mowebauthn_allow_authenticator_type', 'none');
    $mowebauthn_allow_authenticator_type = 'none';
}
?>
<select name="mowebauthn_allow_authenticator_type" id="mowebauthn_allow_authenticator_type">
    <option value="none"<?php if($mowebauthn_allow_authenticator_type === 'none'){?> selected<?php }?>><?php _e('Any', 'mowebauthn-passwordless-login');?></option>
    <option value="platform"<?php if($mowebauthn_allow_authenticator_type === 'platform'){?> selected<?php }?>><?php _e('Platform (e.g. fingerprints, Windows Hello)', 'mowebauthn-passwordless-login');?></option>
    <option value="cross-platform"<?php if($mowebauthn_allow_authenticator_type === 'cross-platform'){?> selected<?php }?>><?php _e('Roaming/cross-platform (e.g. USB security keys)', 'mowebauthn-passwordless-login');?></option>
</select>
<p class="description"><?php _e('If a type is selected, the browser will only prompt for authenticators of selected type when authenticating and user can only register authenticators of selected type.', 'mowebauthn-passwordless-login');?></p>
</td>
</tr>
<tr>
</tr>
</table>
<?php
submit_button(); ?></form>
<?php

}