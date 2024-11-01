<?php 





if(current_user_can('administrator')){ 
    $current_user = get_current_user();
    require dirname(plugin_dir_path( __FILE__ )) .DIRECTORY_SEPARATOR. 'webauthn'.DIRECTORY_SEPARATOR.'configure_webauth.php';
    mowebauthn_configure_webauthn($current_user);
    mowebauthn_show_configured_devices($current_user);

}

function mowebauthn_show_configured_devices($current_user)
{
    global $MowebAuthnDBQueries;

    $currentUserCreds = $MowebAuthnDBQueries->get_user_record(get_current_user_id());
    if($currentUserCreds == null)
		$currentUserTimeStamp = date("Y-m-d H:i:s");
	else
    $currentUserTimeStamp = $currentUserCreds['mowebauthn_timeStamp'] ? $currentUserCreds['mowebauthn_timeStamp'] : date("Y-m-d H:i:s");
    ?>
    <h3><?php _e('Registered Devices', 'mowebauthn-passwordless-login');?></h3>
<div class="table">
<table class="wp-list-table widefat fixed striped">
    <thead>
        <tr>
            <th><?php _e('<b>User</b>', 'mowebauthn-passwordless-login');?></th>
            <th><?php _e('<b>Type</b>', 'mowebauthn-passwordless-login');?></th>
            <th><?php _e('<b>Added</b>', 'mowebauthn-passwordless-login');?></th>
            <th><?php _e('<b>Action <span style="color:red"></span>', 'mowebauthn-passwordless-login');?></th>
        </tr>
        <tr bgcolor="#d1d7dc">
            <td><?php _e($current_user, 'mowebauthn-passwordless-login');?></td>
            <td><?php _e('Windows Hello', 'mowebauthn-passwordless-login');?></td>
            <td><?php _e($currentUserTimeStamp, 'mowebauthn-passwordless-login');?></td>
            <td><?php _e('<a>Delete</a>', 'mowebauthn-passwordless-login');?></td>
        
        </tr>
    </thead>
    <tbody id="wwa-authenticator-list">
        <tr>
            
        </tr>
    </tbody>
    
</table>
</div>

<?php
}
