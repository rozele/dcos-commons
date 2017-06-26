package com.mesosphere.sdk.dcos;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Represents abstraction over DC/OS Certificate Authority.
 * @see "https://docs.mesosphere.com/1.9/networking/tls-ssl/ca-api/"
 */
public interface CertificateAuthorityClient {

    /**
     * Create a new certificate from CSR by contacting certificate authority.
     *
     * @param csr
     * @return
     * @throws IOException
     * @throws CertificateException
     */
    X509Certificate sign(byte[] csr) throws IOException, CertificateException;

}
