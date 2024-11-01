<?php


namespace lbuchs\WebAuthn\Attestation\Format;
use lbuchs\WebAuthn\Attestation\moWebAuthn_AuthenticatorData;
use lbuchs\WebAuthn\WebAuthnException;
use lbuchs\WebAuthn\Binary\moWebAuthn_ByteBuffer;

class moWebAuthn_Apple extends moWebAuthn_FormatBase {
    private $_x5c;

    public function __construct($AttestionObject, moWebAuthn_AuthenticatorData $authenticatorData) {
        parent::__construct($AttestionObject, $authenticatorData);

        $attStmt = $this->_attestationObject['attStmt'];


        if (\array_key_exists('x5c', $attStmt) && \is_array($attStmt['x5c']) && \count($attStmt['x5c']) > 0) {

            $attestnCert = array_shift($attStmt['x5c']);

            if (!($attestnCert instanceof moWebAuthn_ByteBuffer)) {
                throw new WebAuthnException('invalid x5c certificate', WebAuthnException::INVALID_DATA);
            }

            $this->_x5c = $attestnCert->getBinaryString();

            foreach ($attStmt['x5c'] as $chain) {
                if ($chain instanceof moWebAuthn_ByteBuffer) {
                    $this->_x5c_chain[] = $chain->getBinaryString();
                }
            }
        } else {
            throw new WebAuthnException('invalid Apple attestation statement: missing x5c', WebAuthnException::INVALID_DATA);
        }
    }


    /*
     * returns the key certificate in PEM format
     * @return string|null
     */
    public function getCertificatePem() {
        return $this->_createCertificatePem($this->_x5c);
    }

    /**
     * @param string $clientDataHash
     */
    public function validateAttestation($clientDataHash) {
        return $this->_validateOverX5c($clientDataHash);
    }

    /**
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     * @throws WebAuthnException
     */
    public function validateRootCertificate($rootCas) {
        $chainC = $this->_createX5cChainFile();
        if ($chainC) {
            $rootCas[] = $chainC;
        }

        $v = \openssl_x509_checkpurpose($this->getCertificatePem(), -1, $rootCas);
        if ($v === -1) {
            throw new WebAuthnException('error on validating root certificate: ' . \openssl_error_string(), WebAuthnException::CERTIFICATE_NOT_TRUSTED);
        }
        return $v;
    }

    /**
     * validate if x5c is present
     * @param string $clientDataHash
     * @return bool
     * @throws WebAuthnException
     */
    protected function _validateOverX5c($clientDataHash) {
        $publicKey = \openssl_pkey_get_public($this->getCertificatePem());

        if ($publicKey === false) {
            throw new WebAuthnException('invalid public key: ' . \openssl_error_string(), WebAuthnException::INVALID_PUBLIC_KEY);
        }

        // Concatenate authenticatorData and clientDataHash to form nonceToHash.
        $nonceToHash = $this->_authenticatorData->getBinary();
        $nonceToHash .= $clientDataHash;

        $nonce = hash('SHA256', $nonceToHash, true);

        $credCert = openssl_x509_read($this->getCertificatePem());
        if ($credCert === false) {
            throw new WebAuthnException('invalid x5c certificate: ' . \openssl_error_string(), WebAuthnException::INVALID_DATA);
        }

        $keyData = openssl_pkey_get_details(openssl_pkey_get_public($credCert));
        $key = is_array($keyData) && array_key_exists('key', $keyData) ? $keyData['key'] : null;


        $parsedCredCert = openssl_x509_parse($credCert);
        $nonceExtension = isset($parsedCredCert['extensions']['1.2.840.113635.100.8.2']) ? $parsedCredCert['extensions']['1.2.840.113635.100.8.2'] : '';

        
        $asn1Padding = "\x30\x24\xA1\x22\x04\x20";
        if (substr($nonceExtension, 0, strlen($asn1Padding)) === $asn1Padding) {
            $nonceExtension = substr($nonceExtension, strlen($asn1Padding));
        }

        if ($nonceExtension !== $nonce) {
            throw new WebAuthnException('nonce doesn\'t equal the value of the extension with OID 1.2.840.113635.100.8.2', WebAuthnException::INVALID_DATA);
        }

        $authKeyData = openssl_pkey_get_details(openssl_pkey_get_public($this->_authenticatorData->getPublicKeyPem()));
        $authKey = is_array($authKeyData) && array_key_exists('key', $authKeyData) ? $authKeyData['key'] : null;

        if ($key === null || $key !== $authKey) {
            throw new WebAuthnException('credential public key doesn\'t equal the Subject Public Key of credCert', WebAuthnException::INVALID_DATA);
        }

        return true;
    }

}

