<?php


namespace lbuchs\WebAuthn\Attestation\Format;
use lbuchs\WebAuthn\Attestation\moWebAuthn_AuthenticatorData;
use lbuchs\WebAuthn\WebAuthnException;

class moWebAuthn_None extends moWebAuthn_FormatBase {


    public function __construct($AttestionObject, moWebAuthn_AuthenticatorData $authenticatorData) {
        parent::__construct($AttestionObject, $authenticatorData);
    }


    /*
     * returns the key certificate in PEM format
     * @return string
     */
    public function getCertificatePem() {
        return null;
    }

    /**
     * @param string $clientDataHash
     */
    public function validateAttestation($clientDataHash) {
        return true;
    }

    /**
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     * @throws WebAuthnException
     */
    public function validateRootCertificate($rootCas) {
        return true;
    }
}
