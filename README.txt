=== WebAuthn - Passwordless login using Fingerprint, FaceID, Touch ID, Yubikey ===
Contributors: miniOrange, cyberlord92
Tags: WebAuthn, FIDO2, passwordless login, fingerprint, face id, apple id, windows hello, Touch ID, yubikey, web authentication, security, face verification, USB keys, webauthn as a second factor, webauthn 2fa, webauthn two factor authentication, device restriction
Donate link: https://miniorange.com
Requires at least: 4.6
Tested up to: 6.1
Requires PHP: 5.3.0
Stable tag: 1.5.1
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html


[WebAuthn](https://www.miniorange.com/webauthn) is a new way of authenticating your user on the website. WebAuthn by the FIDO2 Alliance allows you to use the login methods already set up on your device, such as, the device passcode, fingerprint, Face ID, Touch ID, Hardware tokens (Yubikey, etc.), USB Keys, Apple ID, etc. Using WebAuthn you can login to your website without needing to worry about passwords and usernames (password less/ username less login). [WebAuthn] (https://www.miniorange.com/webauthn) allows you to authenticate yourself by just clicking and verifying device credentials like touch and face ID, Windows Hello, security key, picture passwords, etc.


== Description ==


Meet the new global standard of web authentication (WebAuthn). WebAuthn is a core component of FIDO2 Alliance which includes protocols that are based on public key cryptography and are strongly resistant to phishing (to varying degrees).
WebAuthn is a browser-based API by FIDO2 that allows web applications to simplify and secure user authentication by using their registered devices (android phones/ iphones, laptops, etc.) as factors. WebAuthn uses public key cryptography by FIDO2 to protect users from advanced phishing attacks. With WebAuthn’s Passwordless login using Fingerprint, FaceID, Touch ID plugin, you can allow your users to login to your website by just entering their device credentials (Fingerprint, windows hello, face ID, touch ID, etc). 


WebAuthn increases the security of your website by providing an additional layer of security and it also enhances the user experience of your website. Webauthn protects your website from many common attacks like phishing, brute force protection, man in the middle attack, malwares, etc.


**[WebAuthn](https://www.miniorange.com/webauthn) requires HTTPS connection or `localhost` for secure authentication**


= Passwordless login with webauthn =
FIDO2/WebAuthn implements the concept of passwordless authentication. The users will enter their username and if their device/keys are configured with WebAuthn then they need to verify it for successful login. If the device is not registered for WebAuthn, then users need to enter their password and then they can configure the WebAuthn. This will make the user experience better by removing the password. It will also increase the security as webauthn is based on public key cryptography authentication and it allows the user to login only if the user is authenticated from the trusted device. 




= WebAuthn as the [second factor](https://plugins.miniorange.com/2-factor-authentication-for-wordpress) =
WebAuthn is also used as the [second factor](https://plugins.miniorange.com/login-to-your-wordpress-site-with-fingerprint-and-faceid-using-webauthn) to add an extra layer of security on your website. In this case the users will enter their username and password to verify their first factor and after that they will be prompted with the WebAuthn for verification of the second layer of security. This will protect your website even if the users' passwords are compromised, because to verify the identity of any user you need to confirm the web authentication with their device.


= Usernameless login with WebAuthn* =
WebAuthn also allows you to provide an option where users can login to your website without entering their username and password. The user will be automatically picked at login via WebAuthn. 


As most of the users do not want to maintain too many credentials so in that case you can allow your users to use their device as the credentials and if the device is verified they will be logged into the site. 


= Device limitation* =
The WebAuthn plugin provides an option where you can put a limit on the number of devices a user can register with WebAuthn. This will be helpful when you want only a particular device to login to the website.
This will allow you to restrict the number of devices a user can use to access your website.


= Role based WebAuthn* = 
With this you can allow WebAuthn to specific user roles. The users who have been allowed to use WebAuthn can login with WebAuthn and others will use their usual wordpress login credentials for access, without getting prompted for the WebAuthn.


= User-specific WebAuthn = 
With this you can select the specific users who can login using WebAuthn to your website. Other users have to use their WordPress credentials to login. 


* supported in the Premium version


== Installation ==




= From your WordPress dashboard =
1. Navigate to `Plugins > Add New` from your WP Admin dashboard.
2. Search for `WebAuthn passwordless login`.
3. Install `WebAuthn passwordless login` by miniOrange and Activate the plugin.


= From WordPress.org =
1. Search for `miniOrange WebAuthn passwordless login` and download it.
2. Unzip and upload the `WebAuthn-passwordless-login-wp` directory to your `/wp-content/plugins/` directory.
3. Activate WebAuthn passwordless login plugin from the Plugins tab of your admin dashboard.






== Frequently Asked Questions ==


= How to enable [WebAuthn](https://www.miniorange.com/webauthn) as username- less login =


This feature is available in the premium version of the plugin. You can buy it on <a href="https://faq.miniorange.com/" target="_blank">Our website</a>.




== Screenshots ==


1. Configure your device for [WebAuthn](https://www.miniorange.com/webauthn)
2. WebAuthn verification on login as the [second factor](https://plugins.miniorange.com/2-factor-authentication-for-wordpress)


== Changelog ==
= 1.5.1 =
* Bug Fixes

= 1.5.0 =
* Bug Fixes
* Second version of the WebAuthn to provide users a secure way of authentication.

= 1.0.0 =
* First version of the WebAuthn to provide users a secure way of authentication.
* WebAuthn as the second factor.

== Upgrade Notice ==

= 1.5.1 =
* Bug Fixes

= 1.5.0 =
* Bug Fixes
* Second version of the WebAuthn to provide users a secure way of authentication.
* WebAuthn

= 1.0.0 =
* First version of the WebAuthn to provide users a secure way of authentication.
* WebAuthn as the second factor.