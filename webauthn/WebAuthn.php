<?php

namespace lbuchs\WebAuthn;
use lbuchs\webauthn\Binary\moWebAuthn_ByteBuffer;
require_once 'WebAuthnException.php';
require_once 'Binary/ByteBuffer.php';
require_once 'Attestation/AttestationObject.php';
require_once 'Attestation/AuthenticatorData.php';
require_once 'Attestation/Format/FormatBase.php';
require_once 'Attestation/Format/None.php';
require_once 'Attestation/Format/AndroidKey.php';
require_once 'Attestation/Format/AndroidSafetyNet.php';
require_once 'Attestation/Format/Apple.php';
require_once 'Attestation/Format/Packed.php';
require_once 'Attestation/Format/Tpm.php';
require_once 'Attestation/Format/U2f.php';
require_once 'CBOR/CborDecoder.php';

class moWebAuthn_WebAuthn {

    private $_rpName;
    private $_rpId;
    private $_rpIdHash;
    private $_challenge;
    private $_signatureCounter;
    private $_caFiles;
    private $_formats;

    /**
     * Initialize a new WebAuthn server
     * @param string $rpName the relying party name
     * @param string $rpId the relying party ID = the domain name
     * @param bool $useBase64UrlEncoding true to use base64 url encoding for binary data in json objects. Default is a RFC 1342-Like serialized string.
     * @throws WebAuthnException
     */
    public function __construct($rpName, $rpId, $allowedFormats=null, $useBase64UrlEncoding=false) {
        $this->_rpName = $rpName;
        $this->_rpId = $rpId;

        $this->_rpIdHash = \hash('sha256', $rpId, true);
        moWebAuthn_ByteBuffer::$useBase64UrlEncoding = !!$useBase64UrlEncoding;
        $supportedFormats = array('android-key', 'android-safetynet', 'apple', 'fido-u2f', 'none', 'packed', 'tpm');
       
        
        if (!\function_exists('\openssl_open')) {
            throw new WebAuthnException('OpenSSL-Module not installed');;
        }

        if (!\in_array('SHA256', \array_map('\strtoupper', \openssl_get_md_methods()))) {
            throw new WebAuthnException('SHA256 not supported by this openssl installation.');
        }

        // default: all format
        if (!is_array($allowedFormats)) {
            $allowedFormats = $supportedFormats;
        }
        $this->_formats = $allowedFormats;

        // validate formats
        $invalidFormats = \array_diff($this->_formats, $supportedFormats);
        if (!$this->_formats || $invalidFormats) {
            throw new WebAuthnException('invalid formats on construct: ' . implode(', ', $invalidFormats));
        }
    }

    /**
     * add a root certificate to verify new registrations
     * @param string $path file path of / directory with root certificates
     */
    public function addRootCertificates($path) {
        if (!\is_array($this->_caFiles)) {
            $this->_caFiles = array();
        }
        $path = \rtrim(\trim($path), '\\/');
        if (\is_dir($path)) {
            foreach (\scandir($path) as $ca) {
                if (\is_file($path . '/' . $ca)) {
                    $this->addRootCertificates($path . '/' . $ca);
                }
            }
        } else if (\is_file($path) && !\in_array(\realpath($path), $this->_caFiles)) {
            $this->_caFiles[] = \realpath($path);
        }
    }

    /**
     * Returns the generated challenge to save for later validation
     * @return ByteBuffer
     */
    public function getChallenge() {
        return $this->_challenge;
    }

    /**
     * generates the object for a key registration
     * provide this data to navigator.credentials.create
     * @param string $userId
     * @param string $userName
     * @param string $userDisplayName
     * @param int $timeout timeout in seconds
     * @param bool $requireResidentKey true, if the key should be stored by the authentication device
     * @param bool|string $requireUserVerification indicates that you require user verification and will fail the operation
     * if the response does not have the UV flag set.
     * Valid values:
     * true = required
     * false = preferred
     *                                             string 'required' 'preferred' 'discouraged'
     * @param bool|null $crossPlatformAttachment   true for cross-platform devices (eg. fido usb),
     *                                             false for platform devices (eg. windows hello, android safetynet),
     *                                             null for both
     * @param array $excludeCredentialIds a array of ids, which are already registered, to prevent re-registration
     * @return \stdClass
     */
    public function getCreateArgs($userId, $userName, $userDisplayName, $timeout=200, $requireResidentKey=false, $requireUserVerification=false, $crossPlatformAttachment=null, $excludeCredentialIds=array()) {

        // validate User Verification Requirement
        if (\is_bool($requireUserVerification)) {
            $requireUserVerification = $requireUserVerification ? 'required' : 'preferred';
        } else if (\is_string($requireUserVerification) && \in_array(\strtolower($requireUserVerification), ['required', 'preferred', 'discouraged'])) {
            $requireUserVerification = \strtolower($requireUserVerification);
        } else {
            $requireUserVerification = 'preferred';
        }

        $args = new \stdClass();
        $args->publicKey = new \stdClass();

        // relying party
        $args->publicKey->rp = new \stdClass();
        $args->publicKey->rp->name = $this->_rpName;
        $args->publicKey->rp->id = $this->_rpId;

        $args->publicKey->authenticatorSelection = new \stdClass();
        $args->publicKey->authenticatorSelection->userVerification = $requireUserVerification;
        if ($requireResidentKey) {
            $args->publicKey->authenticatorSelection->requireResidentKey = true;
        }
        $mowebauthn_allow_authenticator_type = get_site_option('mowebauthn_allow_authenticator_type');
        $args->publicKey->authenticatorSelection->authenticatorAttachment = $mowebauthn_allow_authenticator_type == 'none' ? 'platform' : $mowebauthn_allow_authenticator_type;
        
        // user
        $args->publicKey->user = new \stdClass();
        $randomNess = random_int(000000, 99999999);
        update_site_option($userId+$randomNess,$userId);
        $userId += $randomNess;
        $args->publicKey->user->id = new moWebAuthn_ByteBuffer($userId); // binary
        $args->publicKey->user->name = $userName;
        $args->publicKey->user->displayName = $userDisplayName;

        $args->publicKey->pubKeyCredParams = array();
        $tmp = new \stdClass();
        $tmp->type = 'public-key';
        $tmp->alg = -7; // ES256
        $args->publicKey->pubKeyCredParams[] = $tmp;
        unset ($tmp);

        $tmp = new \stdClass();
        $tmp->type = 'public-key';
        $tmp->alg = -257; // RS256
        $args->publicKey->pubKeyCredParams[] = $tmp;
        unset ($tmp);

        // if there are root certificates added, we need direct attestation to validate
        // against the root certificate. If there are no root-certificates added,
        // anonymization ca are also accepted, because we can't validate the root anyway.
        $attestation = 'indirect';
        if (\is_array($this->_caFiles)) {
            $attestation = 'direct';
        }

        $args->publicKey->attestation = \count($this->_formats) === 1 && \in_array('none', $this->_formats) ? 'none' : $attestation;
        $args->publicKey->extensions = new \stdClass();
        $args->publicKey->extensions->exts = true;
        $args->publicKey->timeout = $timeout * 1000; // microseconds
        $args->publicKey->challenge = $this->_createChallenge(); // binary

        //prevent re-registration by specifying existing credentials
        $args->publicKey->excludeCredentials = array();

        if (is_array($excludeCredentialIds)) {
            foreach ($excludeCredentialIds as $id) {
                $tmp = new \stdClass();
                $tmp->id = $id instanceof moWebAuthn_ByteBuffer ? $id : new moWebAuthn_ByteBuffer($id);  // binary
                $tmp->type = 'public-key';
                $tmp->transports = array('usb', 'ble', 'nfc', 'internal');
                $args->publicKey->excludeCredentials[] = $tmp;
                unset ($tmp);
            }
        }

        return $args;
    }


    /**
     * generates the object for key validation
     * Provide this data to navigator.credentials.get
     * @param array $credentialIds binary
     * @param int $timeout timeout in seconds
     * @param bool $allowUsb allow removable USB
     * @param bool $allowNfc allow Near Field Communication (NFC)
     * @param bool $allowBle allow Bluetooth
     * @param bool $allowInternal allow client device-specific transport. These authenticators are not removable from the client device.
     * @param bool|string $requireUserVerification indicates that you require user verification and will fail the operation
     *                                             if the response does not have the UV flag set.
     *                                             Valid values:
     *                                             true = required
     *                                             false = preferred
     *                                             string 'required' 'preferred' 'discouraged'
     * @return \stdClass
     */
    public function getGetArgs($credentialIds=array(), $timeout=200, $allowUsb=true, $allowNfc=true, $allowBle=true, $allowInternal=true, $requireUserVerification=false) {

        if (\is_bool($requireUserVerification)) {
            $requireUserVerification = $requireUserVerification ? 'required' : 'preferred';
        } else if (\is_string($requireUserVerification) && \in_array(\strtolower($requireUserVerification), ['required', 'preferred', 'discouraged'])) {
            $requireUserVerification = \strtolower($requireUserVerification);
        } else {
            $requireUserVerification = 'preferred';
        }

        $args = new \stdClass();
        $args->publicKey = new \stdClass();
        $args->publicKey->timeout = $timeout * 1000; // microseconds
        $args->publicKey->challenge = $this->_createChallenge();  // binary
        $args->publicKey->userVerification = $requireUserVerification;
        $args->publicKey->rpId = $this->_rpId;
        

        
        if (\is_array($credentialIds) && \count($credentialIds) > 0) {
            $args->publicKey->allowCredentials = array();

            foreach ($credentialIds as $id) {
                $tmp = new \stdClass();
                $tmp->id = $id instanceof moWebAuthn_ByteBuffer ? $id : new moWebAuthn_ByteBuffer($id);  // binary
                $tmp->transports = array();

                if ($allowUsb) {
                    $tmp->transports[] = 'usb';
                }
                if ($allowNfc) {
                    $tmp->transports[] = 'nfc';
                }
                if ($allowBle) {
                    $tmp->transports[] = 'ble';
                }
                if ($allowInternal) {
                    $tmp->transports[] = 'internal';
                }

                $tmp->type = 'public-key';
                $args->publicKey->allowCredentials[] = $tmp;
                unset ($tmp);
            }
        }

        return $args;
    }

    /**
     * returns the new signature counter value.
     * returns null if there is no counter
     * @return ?int
     */
    public function getSignatureCounter() {
        return \is_int($this->_signatureCounter) ? $this->_signatureCounter : null;
    }

    /**
     * process a create request and returns data to save for future logins
     * @param string $clientDataJSON binary from browser
     * @param string $attestationObject binary from browser
     * @param string|ByteBuffer $challenge binary used challange
     * @param bool $requireUserVerification true, if the device must verify user (e.g. by biometric data or pin)
     * @param bool $requireUserPresent false, if the device must NOT check user presence (e.g. by pressing a button)
     * @return \stdClass
     * @throws WebAuthnException
     */
    public function processCreate($clientDataJSON, $attestationObject, $challenge, $requireUserVerification=false, $requireUserPresent=true) {
        
        global $current_user;
        $clientDataHash = \hash('sha256', $clientDataJSON, true);
        $clientData = \json_decode($clientDataJSON);
        $challenge = $challenge instanceof moWebAuthn_ByteBuffer ? $challenge : new moWebAuthn_ByteBuffer($challenge);

        if (!\is_object($clientData)) {
            
            throw new WebAuthnException('invalid client data', WebAuthnException::INVALID_DATA);
        }
        if (!\property_exists($clientData, 'type') || $clientData->type !== 'webauthn.create') {

            throw new WebAuthnException('invalid type', WebAuthnException::INVALID_TYPE);
        }
        if (!\property_exists($clientData, 'challenge') || moWebAuthn_ByteBuffer::fromBase64Url($clientData->challenge)->getBinaryString() !== $challenge->getBinaryString()) {

            throw new WebAuthnException('invalid challenge', WebAuthnException::INVALID_CHALLENGE);
        }
        
        if (!\property_exists($clientData, 'origin') || !$this->_checkOrigin($clientData->origin)) {
            throw new WebAuthnException('invalid origin', WebAuthnException::INVALID_ORIGIN);
        }
        

        $attestationObject = new Attestation\moWebAuthn_AttestationObject($attestationObject, $this->_formats);
        if (!$attestationObject->validateRpIdHash($this->_rpIdHash)) {
            throw new WebAuthnException('invalid rpId hash', WebAuthnException::INVALID_RELYING_PARTY);
        }
        if (!$attestationObject->validateAttestation($clientDataHash)) {
            
            throw new WebAuthnException('invalid certificate signature', WebAuthnException::INVALID_SIGNATURE);
        }
        if (is_array($this->_caFiles) && $attestationObject->validateRootCertificate($this->_caFiles)) {
            throw new WebAuthnException('invalid root certificate', WebAuthnException::CERTIFICATE_NOT_TRUSTED);
        }
        if ($requireUserPresent && !$attestationObject->getAuthenticatorData()->getUserPresent()) {
            throw new WebAuthnException('user not present during authentication', WebAuthnException::USER_PRESENT);
        }
        if ($requireUserVerification && !$attestationObject->getAuthenticatorData()->getUserVerified()) {
            throw new WebAuthnException('user not verificated during authentication', WebAuthnException::USER_VERIFICATED);
        }
        $signCount = $attestationObject->getAuthenticatorData()->getSignCount();
        if ($signCount > 0) {
            $this->_signatureCounter = $signCount;
        }   
        $data = new \stdClass();
        $data->rpId = $this->_rpId;
        $data->credentialId = $attestationObject->getAuthenticatorData()->getCredentialId();
        $data->credentialPublicKey = $attestationObject->getAuthenticatorData()->getPublicKeyPem();
        $data->certificateChain = $attestationObject->getCertificateChain();
        $data->certificate = $attestationObject->getCertificatePem();
        $data->signatureCounter = $this->_signatureCounter;
        $data->AAGUID = $attestationObject->getAuthenticatorData()->getAAGUID();
        
        global $MowebAuthnDBQueries;
        $MowebAuthnDBQueries->mowebauthn_insert_credentials($current_user->ID,$data->rpId,base64_encode($data->credentialId),base64_encode($data->credentialPublicKey),base64_encode($data->certificateChain),base64_encode($data->certificate),base64_encode($data->signatureCounter),base64_encode($data->AAGUID));     


        return $data;
    }


    /**
     * process a get request
     * @param string $clientDataJSON binary from browser
     * @param string $authenticatorData binary from browser
     * @param string $signature binary from browser
     * @param string $credentialPublicKey string PEM-formated public key from used credentialId
     * @param string|ByteBuffer $challenge  binary from used challange
     * @param int $prevSignatureCnt signature count value of the last login
     * @param bool $requireUserVerification true, if the device must verify user (e.g. by biometric data or pin)
     * @param bool $requireUserPresent true, if the device must check user presence (e.g. by pressing a button)
     * @return boolean true if get is successful
     * @throws WebAuthnException
     */
    public function processGet($clientDataJSON, $authenticatorData, $signature, $credentialPublicKey, $challenge, $prevSignatureCnt=null, $requireUserVerification=false, $requireUserPresent=true) {

        $authenticatorObj = new Attestation\moWebAuthn_AuthenticatorData($authenticatorData);
        $clientDataHash = \hash('sha256', $clientDataJSON, true);
        $clientData = \json_decode($clientDataJSON);
        $challenge = $challenge instanceof moWebAuthn_ByteBuffer ? $challenge : new moWebAuthn_ByteBuffer($challenge);

        if (!\is_object($clientData)) {
            throw new WebAuthnException('invalid client data', WebAuthnException::INVALID_DATA);
        }

        if (!\property_exists($clientData, 'type') || $clientData->type !== 'webauthn.get') {
            throw new WebAuthnException('invalid type', WebAuthnException::INVALID_TYPE);
        }

        if (!\property_exists($clientData, 'challenge') || moWebAuthn_ByteBuffer::fromBase64Url($clientData->challenge)->getBinaryString() !== $challenge->getBinaryString()) {
            throw new WebAuthnException('invalid challenge', WebAuthnException::INVALID_CHALLENGE);
        }

        if (!\property_exists($clientData, 'origin') || !$this->_checkOrigin($clientData->origin)) {
            throw new WebAuthnException('invalid origin', WebAuthnException::INVALID_ORIGIN);
        }

        if ($authenticatorObj->getRpIdHash() !== $this->_rpIdHash) {
            throw new WebAuthnException('invalid rpId hash', WebAuthnException::INVALID_RELYING_PARTY);
        }

        if ($requireUserPresent && !$authenticatorObj->getUserPresent()) {
            throw new WebAuthnException('user not present during authentication', WebAuthnException::USER_PRESENT);
        }

        if ($requireUserVerification && !$authenticatorObj->getUserVerified()) {
            throw new WebAuthnException('user not verificated during authentication', WebAuthnException::USER_VERIFICATED);
        }

        $dataToVerify = '';
        $dataToVerify .= $authenticatorData;
        $dataToVerify .= $clientDataHash;

        $publicKey = \openssl_pkey_get_public($credentialPublicKey);
        if ($publicKey === false) {
            throw new WebAuthnException('public key invalid', WebAuthnException::INVALID_PUBLIC_KEY);
        }

        if (\openssl_verify($dataToVerify, $signature, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            throw new WebAuthnException('invalid signature', WebAuthnException::INVALID_SIGNATURE);
        }

        $signatureCounter = $authenticatorObj->getSignCount();
        if ($signatureCounter > 0) {
            $this->_signatureCounter = $signatureCounter;
            if ($prevSignatureCnt !== null && $prevSignatureCnt >= $signatureCounter) {
                throw new WebAuthnException('signature counter not valid', WebAuthnException::SIGNATURE_COUNTER);
            }
        }
        
        return true;
    }

    // -----------------------------------------------
    // PRIVATE
    // -----------------------------------------------

    /**
     * checks if the origin matchs the RP ID
     * @param string $origin
     * @return boolean
     * @throws WebAuthnException
     */
    private function _checkOrigin($origin) {
        if ($this->_rpId !== 'localhost' && \parse_url($origin, PHP_URL_SCHEME) !== 'https') {
            return false;
        }

        $host = \parse_url($origin, PHP_URL_HOST);
        $host = \trim($host, '.');

        return \preg_match('/' . \preg_quote($this->_rpId) . '$/i', $host) === 1;
    }

    /**
     * generates a new challange
     * @param int $length
     * @return string
     * @throws WebAuthnException
     */
    private function _createChallenge($length = 32) {
        if (!$this->_challenge) {
            $this->_challenge = moWebAuthn_ByteBuffer::randomBuffer($length);
            
        }
        return $this->_challenge;
    }
}
