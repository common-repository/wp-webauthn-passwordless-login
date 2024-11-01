<?php
global $wpdb;
global $current_user;
global $Mo2fdbQueries;
$current_user = wp_get_current_user();
$email = $current_user->user_email;
?>
    <div class="mowebauthn_support_layout">
        <h3><?php echo 'Support';?></h3>
            <form name="f" method="post" action="">
                <div><?php echo 'Need any help setting it up? Facing any issues? Shoot us a query and we will get back to you. ';?><br /><br /></div>
            
                <br>
                
                <div>
                    <table style="width:95%;">
                        <tr><td>
                            <input type="email" id="mowebauthn_query_email"  style="width:100%" name="mowebauthn_query_email" value="<?php echo $email ? $email : $current_user->user_email; ?>" placeholder="<?php echo ('Enter your email');?>" required="true" />
                            </td>
                        </tr>
                        <tr><td>
                            <input type="text" style="width:100% !important;" name="query_phone" id="query_phone" value="" placeholder="<?php echo ('Enter your phone');?>"/>
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <textarea id="mowebauthn_query" name="mowebauthn_query" style="resize: vertical;border-radius:4px;width:100%;height:143px;" onkeyup="mowebauthn_valid(this)" onblur="mowebauthn_valid(this)" onkeypress="mowebauthn_valid(this)" placeholder="<?php echo ('Write your query here');?>"></textarea>
                            </td>
                        </tr>
                    </table>
                </div>
                <input type="submit" name="mowebauthn_send_query" id="mowebauthn_send_query" value="<?php echo ('Submit Query');?>" style="margin-bottom:3%;" class="button button-primary button-large" />
            </form>
            <br />          
    </div>
    <br>
    <script>
        function mowebauthn_valid(f) {
            !(/^[a-zA-Z?,.\(\)\/@ 0-9]*$/).test(f.value) ? f.value = f.value.replace(/[^a-zA-Z?,.\(\)\/@ 0-9]/, '') : null;
        }
    </script>
<?php

?>