package com.mesosphere.sdk.dcos;

import com.mesosphere.sdk.dcos.ca.CAException;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;

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
    X509Certificate sign(byte[] csr) throws IOException, CertificateException, CAException;

    /**
     * Retrieves complete certificate chain including a root CA certificate for given certificate.
     * @param certificate
     * @return
     * @throws IOException
     * @throws CertificateException
     */
    Collection<X509Certificate> chainWithRootCert(
            X509Certificate certificate) throws IOException, CertificateException, CAException;

}
