<?php 


if( current_user_can('administrator')){ ?>
<form method="post" action="">
<table class="form-table" >
<tr>
<th scope="row" style="width:400px"><label><?php _e('Role Based Webauthn <b style = "color:red"></b>', 'mowebauthn-passwordless-login');?></label></th>
<td>
<div>

<div>
<input type="checkbox" name="mowebauthn_administrator" style="margin-left: 2%;" disabled checked="checked">Administrator
<input type="checkbox" name="mowebauthn_subscriber" style="margin-left: 2%;" disabled >Subscriber
<input type="checkbox" name="mowebauthn_author" style="margin-left: 2%;" disabled >Author</div><br>
<input type="checkbox" name="mowebauthn_contributor" style="margin-left: 2%;" disabled >Contributor
<input type="checkbox" name="mowebauthn_editor" style="margin-left: 2%;" disabled >Editor</div>
<p class="description"><?php _e('Using this Feature you can allow webauthn to specific user roles.');?></p>
</td>
</tr>

<tr>
<th scope="row"><label for="mowebauthn_MFA"><?php _e('Multiple 2fa on login <b style = "color:red"></b>', 'mowebauthn-passwordless-login');?></label></th>
<td>
	<input type="checkbox" name="mowebauthn_webauthn" style="margin-left: 2%;" disabled checked="checked">Webauthn<br><br>
	<input type="checkbox" name="mowebauthn_google_authenticator" style="margin-left: 2%;" disabled >Google Authenticator<br><br>
	<input type="checkbox" name="mowebauthn_OTPSMS" style="margin-left: 2%;" disabled >OTP Over SMS<br><br>
	<input type="checkbox" name="mowebauthn_OTPEMail" style="margin-left: 2%;" disabled >OTP Over Email<br><br>
	<input type="checkbox" name="mowebauthn_PushNotification" style="margin-left: 2%;" disabled >Push Notification</div><br><br>

    <p class="description"><?php _e('With this you can enable webauthn as choice of second factor with above methods.');?></p>
</td>
</tr>
<tr>
<th scope="row"><label for="mowebauthn_redirection"><?php _e('Redirect user based on their role after successful login.');?></label></th>
<td>
   
    <p class="description"><?php _e('Choose the Redirect URL where you want your users to get redirected after they login to your website.');?></p>
</td>
</tr>
<th scope="row"><label for="mowebauthn_on_custom_login_form"><?php _e('Webauthn for custom login form', 'mowebauthn-passwordless-login');?></label></th>
<td>


<p class="description"><?php _e('We do support all login forms like woocommerce, theme my login, ultimate member,etc. Please contact if you want us to support your login from.');?></p>
</td>
</tr>
<tr>
<th scope="row"><label for="mowebauthn_report"><?php _e('Report of login', 'mowebauthn-passwordless-login');?></label></th>
<td>
        <p class="description"><?php _e('Get reports of user login from both webauthn and without webauthn.', 'mowebauthn-passwordless-login');?></p>
</td>
</tr>
</table>
</form>
<?php

}