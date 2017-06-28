package com.mesosphere.sdk.offer.evaluate.security;

/**
 * Provides a way to generate paths for secrets storing a private key, a certificate and a keystore.
 */
public class SecretNameGenerator {

    private String serviceName;
    private String taskName;
    private String transportEncryptionName;

    public SecretNameGenerator(String serviceName, String taskName, String transportEncryptionName) {
        this.serviceName = serviceName;
        this.transportEncryptionName = transportEncryptionName;
        this.taskName = taskName;
    }

    public String getCertificatePath() {
        return getSecretPath("certificate");
    }

    public String getPrivateKeyPath() {
        return getSecretPath("private-key");
    }

    public String getRootCACertPath() {
        return getSecretPath("root-ca-certificate");
    }

    public String getKeyStorePath() {
        return getSecretPath("keystore");
    }

    public String getTrustStorePath() {
        return getSecretPath("truststore");
    }

    public String getCertificateMountPath() {
        return getMountPath("crt");
    }

    public String getPrivateKeyMountPath() {
        return getMountPath("key");
    }

    public String getRootCACertMountPath() {
        return getMountPath("ca");
    }

    public String getKeyStoreMountPath() {
        return getMountPath("keystore");
    }

    public String getTrustStoreMountPath() {
        return getMountPath("truststore");
    }

    private String getSecretPath(String name) {
        return String.format("%s/%s/%s/%s", serviceName, taskName, transportEncryptionName, name);
    }

    private String getMountPath(String suffix) {
        return String.format("%s.%s", transportEncryptionName, suffix);
    }

}
