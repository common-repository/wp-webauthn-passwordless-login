<?php 
global $moppm_dirname;
    $email = get_site_option("email");
    if (empty($email)) {
        $user = wp_get_current_user();
        $email = $user->user_email;
    }
    $imagepath = plugins_url('wp-webauthn-passwordless-login'.DIRECTORY_SEPARATOR .'includes'.DIRECTORY_SEPARATOR .'images'.DIRECTORY_SEPARATOR );
    // function moweb_deactivate(){
?>
<!-- The Modal -->
    <div id="moppm_feedback_modal" class="mo_modal" style="width:90%; margin-left:12%; margin-top:5%; text-align:center; margin-left;">

        <!-- Modal content -->
        <div class="mo_wpns_modal-content" style="width:50%;">
            <h3 style="margin: 2%; text-align:center;"><b>Your feedback</b><span class="mo_wpns_close" style="cursor: pointer">&times;</span>
            </h3>
            <hr style="width:75%;">
            
            <form name="f1" method="post" action="" id="moppm_feedback">
                <?php wp_nonce_field("moppm_feedback");?>
                <input type="hidden" name="option" value="moppm_feedback"/>
                    <h4 style="margin: 2%; text-align:center;">Please help us to improve our plugin by giving your opinion.<br></h4>
                    
                    <div id="smi_rate" style="text-align:center">
                    <input type="radio" name="rate" id="angry" value="1"/>
                        <label for="angry"><img class="sm" src="<?php echo esc_url_raw($imagepath) . 'angry.png'; ?>" />
                        </label>
                        
                    <input type="radio" name="rate" id="sad" value="2"/>
                        <label for="sad"><img class="sm" src="<?php echo esc_url_raw($imagepath) . 'sad.png'; ?>" />
                        </label>
                    
                    
                    <input type="radio" name="rate" id="neutral" value="3"/>
                        <label for="neutral"><img class="sm" src="<?php echo esc_url_raw($imagepath). 'normal1.png'; ?>" />
                        </label>
                        
                    <input type="radio" name="rate" id="smile" value="4"/>
                        <label for="smile">
                        <img class="sm" src="<?php echo esc_url_raw($imagepath) . 'smile.png'; ?>" />
                        </label>
                        
                    <input type="radio" name="rate" id="happy" value="5" checked/>
                        <label for="happy"><img class="sm" src="<?php echo esc_url_raw($imagepath) . 'happy.png'; ?>" />
                        </label>
                        
                    <div id="outer" style="visibility:visible"><span id="result">Thank you for appreciating our work</span></div>
                    </div><br>
                    <hr style="width:75%;">

                    <div style="text-align:center;">
                        
                        <div style="display:inline-block; width:60%;">
                        <input type="email" id="query_mail" name="query_mail" style="text-align:center; border:0px solid black; border-style:solid; background:#f0f3f7; width:20vw;border-radius: 6px;"
                              placeholder="your email address" required value="<?php echo $email; ?>" readonly="readonly"/>
                        
                        <input type="radio" name="edit" id="edit" onclick="editName()" value=""/>
                        <label for="edit"><img class="editable" src="<?php echo esc_url_raw($imagepath) . '61456.png'; ?>" />
                        </label>
                        
                        </div>
                        <br><br>
                        <textarea id="moppm_query_feedback" name="moppm_query_feedback" rows="4" style="width: 60%"
                              placeholder="Tell us what happened!"></textarea>
                        <br><br>
                          <input type="checkbox" name="get_reply" value="reply" checked>miniOrange representative will reach out to you at the email-address entered above.</input>
                    </div>
                    <br>
                   
                    <div class="mo-modal-footer" style="text-align: center;margin-bottom: 2%">
                        <input type="submit" name="moppm_feedback_submit"
                               style="background-color:#224fa2; padding: 1% 3% 1% 3%;color: white;cursor: pointer;" value="Send"/>
                        <span width="30%">&nbsp;&nbsp;</span>
                        <input type="button" name="moppm_skip_feedback"
                               style="background-color:#224fa2; padding: 1% 3% 1% 3%;color: white;cursor: pointer;" value="Skip" onclick="document.getElementById('moppm_feedback_form_close').submit();"/>
                    </div>
                </div>  
                <script>                           
                        const INPUTS = document.querySelectorAll('#smi_rate input');
                        INPUTS.forEach(el => el.addEventListener('click', (e) => updateValue(e)));
                        
                        function editName(){
                            document.querySelector('#query_mail').removeAttribute('readonly');
                            document.querySelector('#query_mail').focus();
                            return false;
                        }
                        function updateValue(e) {
                            document.querySelector('#outer').style.visibility="visible";
                            var result = 'Thank you for appreciating our work';
                            switch(e.target.value){
                                case '1':   result = 'Not happy with our plugin ? Let us know what went wrong';
                                            break;
                                case '2':   result = 'Found any issues? Let us know and we\'ll fix it ASAP';
                                            break;
                                case '3':   result = 'Let us know if you need any help';
                                            break;
                                case '4':   result = 'We\'re glad that you are happy with our plugin';
                                            break;
                                case '5':   result = 'Thank you for appreciating our work';
                                            break;
                            }
                            document.querySelector('#result').innerHTML = result;
                        }
                </script>
                <style>
                    .editable{
                        text-align:center;
                        width:1em;
                        height:1em;
                    }
                    .sm {
                        text-align:center;
                        width: 2vw;
                        height: 2vw;
                        padding: 1vw;
                    }

                    input[type=radio] {
                        display: none;
                    }

                    .sm:hover {
                        opacity:0.6;
                        cursor: pointer;
                    }

                    .sm:active {
                        opacity:0.4;
                        cursor: pointer;
                    }

                    input[type=radio]:checked + label > .sm {
                        border: 2px solid #21ecdc;
                    }
                    @import url('https://fonts.googleapis.com/css2?family=Varta:wght@300&display=swap');

.mo_wpns_modal {
position: fixed !important;
top: 0;
right: 0;
bottom: 0;
left: 0;
z-index: 100000 !important;
display: none;
overflow: hidden !important;
-webkit-overflow-scrolling: touch;
outline: 0;
display:block;
}
.mo_modal {
    display: none;
    overflow: hidden;
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    left: 0;
    z-index: 1050;
    -webkit-overflow-scrolling: touch;
    outline: 0;

}

.mo_wpns_modal-content {
    position: relative;
    background-color: #ffffff;
    border: 1px solid #999999;
    border: 1px solid rgba(0, 0, 0, 0.2);
    border-radius: 6px;
    -webkit-box-shadow: 0 3px 9px rgba(0, 0, 0, 0.5);
    box-shadow: 0 3px 9px rgba(0, 0, 0, 0.5);
    -webkit-background-clip: padding-box;
    background-clip: padding-box;
    outline: 0;
    margin-left: 20%;
    margin-right: 24%;
    margin-top:6%;
}

.mo_wpns_close {
    color: #aaaaaa;
    float: right;
    font-size: 28px;
    font-weight: bold;
}



                </style>
            </form>
            <form name="f1" method="post" action="" id="moppm_feedback_form_close">
                <?php wp_nonce_field("moppm_feedback");?>
                <input type="hidden" name="option" value="moppm_skip_feedback"/>
            </form>

        </div>

    </div>

    <script>
        jQuery('#deactivate-wp-webauthn-passwordless-login').click(function () {

            var mo_modal = document.getElementById('moppm_feedback_modal');

            var span = document.getElementsByClassName("mo_wpns_close")[0];

// When the user clicks the button, open the Moppm_modal
            mo_modal.style.display = "block";
            document.querySelector("#moppm_query_feedback").focus();
            span.onclick = function () {
                mo_modal.style.display = "none";
            }

            // When the user clicks anywhere outside of the Moppm_modal, Moppm_close it
            window.onclick = function (event) {
                if (event.target == mo_modal) {
                    mo_modal.style.display = "none";
                }
            }
            return false;

        });
    </script>
    