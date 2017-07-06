package com.mesosphere.sdk.offer.evaluate.security;

import com.mesosphere.sdk.dcos.CertificateAuthorityClient;
import com.mesosphere.sdk.dcos.ca.CAException;
import com.mesosphere.sdk.dcos.ca.PEMHelper;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UncheckedIOException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.stream.Collectors;

/**
 * Generates all necessary artifacts for given task.
 */
public class TLSArtifactsGenerator {

    private String serviceName;
    private String taskName;
    private KeyPairGenerator keyPairGenerator;
    private CertificateAuthorityClient certificateAuthorityClient;

    public TLSArtifactsGenerator(
            String serviceName,
            String taskName,
            KeyPairGenerator keyPairGenerator,
            CertificateAuthorityClient certificateAuthorityClient) {
        this.serviceName = serviceName;
        this.taskName = taskName;
        this.keyPairGenerator = keyPairGenerator;
        this.certificateAuthorityClient = certificateAuthorityClient;
    }

    public TLSArtifacts generate() throws Exception {
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Get new end-entity certificate from CA
        X509Certificate certificate = certificateAuthorityClient.sign(generateCSR(keyPair));

        // Get end-entity bundle with Root CA certificate
        ArrayList<X509Certificate> certificateChain = certificateChain = (ArrayList<X509Certificate>)
                certificateAuthorityClient.chainWithRootCert(certificate);

        // Build end-entity certificate with CA chain without Root CA certificate
        ArrayList<X509Certificate> endEntityCertificateWithChain = new ArrayList<>();
        endEntityCertificateWithChain.add(certificate);
        // Add all possible certificates in the chain
        if (certificateChain.size() > 1) {
            endEntityCertificateWithChain.addAll(certificateChain.subList(0, certificateChain.size() - 1));
        }
        // Convert to pem and join to a single string
        String certPEM = endEntityCertificateWithChain.stream()
                .map(cert -> {
                    try {
                        return PEMHelper.toPEM(cert);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                })
                .collect(Collectors.joining());

        // Serialize private key and Root CA cert to PEM format
        String privateKeyPEM = PEMHelper.toPEM(keyPair.getPrivate());
        String rootCACertPEM = PEMHelper.toPEM(
                certificateChain.get(certificateChain.size() - 1));

        // Create keystore and trust store
        KeyStore keyStore = createEmptyKeyStore();
        // TODO(mh): Make configurable "cert"
        keyStore.setCertificateEntry("cert", certificate);

        // KeyStore expects complete chain with end-entity certificate
        certificateChain.add(0, certificate);
        Certificate[] keyStoreChain = certificateChain.toArray(
                new Certificate[certificateChain.size()]);

        // TODO(mh): Make configurable "private-key"
        keyStore.setKeyEntry("private-key", keyPair.getPrivate(), new char[0], keyStoreChain);

        KeyStore trustStore = createEmptyKeyStore();
        trustStore.setCertificateEntry("dcos-root", certificateChain.get(certificateChain.size() - 1));

        return new TLSArtifacts(certPEM, privateKeyPEM, rootCACertPEM, keyStore, trustStore);
    }

    private KeyStore createEmptyKeyStore()
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, new char[0]);
        return keyStore;
    }

    private byte[] generateCSR(
            KeyPair keyPair) throws IOException, OperatorCreationException {

        CertificateNamesGenerator certificateNamesGenerator = new CertificateNamesGenerator(
                serviceName, taskName);

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        extensionsGenerator.addExtension(
                Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

        extensionsGenerator.addExtension(
                Extension.extendedKeyUsage,
                true,
                new ExtendedKeyUsage(
                        new KeyPurposeId[] {
                                KeyPurposeId.id_kp_clientAuth,
                                KeyPurposeId.id_kp_serverAuth
                        }
                ));

        extensionsGenerator.addExtension(
                Extension.subjectAlternativeName, true, certificateNamesGenerator.getSANs());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());

        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                certificateNamesGenerator.getSubject(), keyPair.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PemWriter writer = new PemWriter(new OutputStreamWriter(os, Charset.forName("UTF-8")));
        writer.writeObject(new JcaMiscPEMGenerator(csr));
        writer.flush();

        return os.toByteArray();
    }

}
