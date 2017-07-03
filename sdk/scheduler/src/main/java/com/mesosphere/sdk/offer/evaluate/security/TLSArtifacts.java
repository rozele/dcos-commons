package com.mesosphere.sdk.offer.evaluate.security;

import java.security.KeyStore;

/**
 * A {@link TLSArtifacts} is a container that holds various objects related to single TLS certificate.
 */
public class TLSArtifacts {

    private String certPEM;
    private String privateKeyPEM;
    private String rootCACertPEM;
    private KeyStore keyStore;
    private KeyStore trustStore;

    public TLSArtifacts(
            String certPEM,
            String privateKeyPEM,
            String rootCACertPEM,
            KeyStore keyStore,
            KeyStore trustStore) {
        this.certPEM = certPEM;
        this.privateKeyPEM = privateKeyPEM;
        this.rootCACertPEM = rootCACertPEM;
        this.keyStore = keyStore;
        this.trustStore = trustStore;
    }

    public String getCertPEM() {
        return certPEM;
    }

    public String getPrivateKeyPEM() {
        return privateKeyPEM;
    }

    public String getRootCACertPEM() {
        return rootCACertPEM;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public KeyStore getTrustStore() {
        return trustStore;
    }
}
