<?php

namespace lbuchs\WebAuthn\Attestation;
use lbuchs\WebAuthn\WebAuthnException;
use lbuchs\WebAuthn\CBOR\moWebAuthn_CborDecoder;
use lbuchs\WebAuthn\Binary\moWebAuthn_ByteBuffer;

class moWebAuthn_AttestationObject {
    private $_authenticatorData;
    private $_attestationFormat;

    public function __construct($binary , $allowedFormats) {
        $enc = moWebAuthn_CborDecoder::decode($binary);
        if (!\is_array($enc) || !\array_key_exists('fmt', $enc) || !is_string($enc['fmt'])) {
            throw new WebAuthnException('invalid attestation format', WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('attStmt', $enc) || !\is_array($enc['attStmt'])) {
            throw new WebAuthnException('invalid attestation format (attStmt not available)', WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('authData', $enc) || !\is_object($enc['authData']) || !($enc['authData'] instanceof moWebAuthn_ByteBuffer)) {
            throw new WebAuthnException('invalid attestation format (authData not available)', WebAuthnException::INVALID_DATA);
        }

        $this->_authenticatorData = new moWebAuthn_AuthenticatorData($enc['authData']->getBinaryString());
        
        if (!in_array($enc['fmt'], $allowedFormats)) {
            throw new WebAuthnException('invalid atttestation format: ' . $enc['fmt'], WebAuthnException::INVALID_DATA);
        }

        
        switch ($enc['fmt']) {
            case 'android-key': $this->_attestationFormat = new Format\moWebAuthn_AndroidKey($enc, $this->_authenticatorData); break;
            case 'android-safetynet': $this->_attestationFormat = new Format\moWebAuthn_AndroidSafetyNet($enc, $this->_authenticatorData); break;
            case 'apple': $this->_attestationFormat = new Format\moWebAuthn_Apple($enc, $this->_authenticatorData); break;
            case 'fido-u2f': $this->_attestationFormat = new Format\moWebAuthn_U2f($enc, $this->_authenticatorData); break;
            case 'none': $this->_attestationFormat = new Format\moWebAuthn_None($enc, $this->_authenticatorData); break;
            case 'packed': $this->_attestationFormat = new Format\moWebAuthn_Packed($enc, $this->_authenticatorData); break;
            case 'tpm': $this->_attestationFormat = new Format\moWebAuthn_Tpm($enc, $this->_authenticatorData); break;
            default: throw new WebAuthnException('invalid attestation format: ' . $enc['fmt'], WebAuthnException::INVALID_DATA);
        }
    }

    /**
     * returns the attestation public key in PEM format
     * @return AuthenticatorData
     */
    public function getAuthenticatorData() {
        return $this->_authenticatorData;
    }

    /**
     * returns the certificate chain as PEM
     * @return string|null
     */
    public function getCertificateChain() {
        return $this->_attestationFormat->getCertificateChain();
    }

    /**
     * return the certificate issuer as string
     * @return string
     */
    public function getCertificateIssuer() {
        $pem = $this->getCertificatePem();
        $issuer = '';
        if ($pem) {
            $certInfo = \openssl_x509_parse($pem);
            if (\is_array($certInfo) && \is_array($certInfo['issuer'])) {
                if ($certInfo['issuer']['CN']) {
                    $issuer .= \trim($certInfo['issuer']['CN']);
                }
                if ($certInfo['issuer']['O'] || $certInfo['issuer']['OU']) {
                    if ($issuer) {
                        $issuer .= ' (' . \trim($certInfo['issuer']['O'] . ' ' . $certInfo['issuer']['OU']) . ')';
                    } else {
                        $issuer .= \trim($certInfo['issuer']['O'] . ' ' . $certInfo['issuer']['OU']);
                    }
                }
            }
        }

        return $issuer;
    }

    /**
     * return the certificate subject as string
     * @return string
     */
    public function getCertificateSubject() {
        $pem = $this->getCertificatePem();
        $subject = '';
        if ($pem) {
            $certInfo = \openssl_x509_parse($pem);
            if (\is_array($certInfo) && \is_array($certInfo['subject'])) {
                if ($certInfo['subject']['CN']) {
                    $subject .= \trim($certInfo['subject']['CN']);
                }
                if ($certInfo['subject']['O'] || $certInfo['subject']['OU']) {
                    if ($subject) {
                        $subject .= ' (' . \trim($certInfo['subject']['O'] . ' ' . $certInfo['subject']['OU']) . ')';
                    } else {
                        $subject .= \trim($certInfo['subject']['O'] . ' ' . $certInfo['subject']['OU']);
                    }
                }
            }
        }

        return $subject;
    }

    /**
     * returns the key certificate in PEM format
     * @return string
     */
    public function getCertificatePem() {
        return $this->_attestationFormat->getCertificatePem();
    }

    /**
     * checks validity of the signature
     * @param string $clientDataHash
     * @return bool
     * @throws WebAuthnException
     */
    public function validateAttestation($clientDataHash) {
        return $this->_attestationFormat->validateAttestation($clientDataHash);
    }

    /**
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     * @throws WebAuthnException
     */
    public function validateRootCertificate($rootCas) {
        return $this->_attestationFormat->validateRootCertificate($rootCas);
    }

    /**
     * checks if the RpId-Hash is valid
     * @param string$rpIdHash
     * @return bool
     */
    public function validateRpIdHash($rpIdHash) {
        return $rpIdHash === $this->_authenticatorData->getRpIdHash();
    }
}
