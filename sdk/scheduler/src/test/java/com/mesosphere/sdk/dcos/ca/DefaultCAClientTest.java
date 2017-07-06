package com.mesosphere.sdk.dcos.ca;

import com.mesosphere.sdk.dcos.auth.StaticTokenProvider;
import com.mesosphere.sdk.dcos.http.DcosHttpClientBuilder;
import org.apache.http.client.HttpClient;
import org.apache.http.client.fluent.Executor;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Collection;

public class DefaultCAClientTest {

    private String TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiJhZG1pbiIsImV4cCI6MTQ5OTAxNTQ2NH0.PSEvegn859wXxswcmjMybGBbA20s2KSpag_CYRaDqeT4ICwiVwN2TkpxJUhnytuXFOchgucHGAW0UREJXnq88l0FgtcRIOxgyXFN5C4QOI5bt7wGtwudVTteDhaibN3NDqiMCvLmtgZDsqrDhepLpY4tFncNBSBj9NJWznLTzkjKgf0FCKw5c2bXUgB4D6EGMFaJg-JO4u5Aa7kf2nV7W0WBFnQOkClaBrr_--MbFYdz3Cls4H7YeHFiS3SnmH7NhEDbvhCIrNNhAGH_vvsrZEjyc0Zj18pl6bsH3_T1tafY_WwQHiIcTb4hmHQasl0ui0aRswierwSrhCZnzyaU-g";

    private KeyPairGenerator KEY_PAIR_GENERATOR;
    private int RSA_KEY_SIZE = 2048;
    @SuppressWarnings("PMD.AvoidUsingHardCodedIP")
    private String TEST_IP_ADDR = "127.0.0.1";

    private URL CA_BASE_URL;

    @Before
    public void init() throws NoSuchAlgorithmException, MalformedURLException {
        KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("RSA");
        KEY_PAIR_GENERATOR.initialize(RSA_KEY_SIZE);
        CA_BASE_URL = new URL("https://172.17.0.2/ca/api/v2/");
    }

    private Executor createAuthenticatedExecutor() throws NoSuchAlgorithmException {
        HttpClient httpClient = new DcosHttpClientBuilder()
                .disableTLSVerification()
                .setTokenProvider(new StaticTokenProvider(TOKEN))
                .build();
        return Executor.newInstance(httpClient);
    }

    private byte[] createCSR() throws IOException, OperatorCreationException {
        KeyPair keyPair = KEY_PAIR_GENERATOR.generateKeyPair();

        X500NameBuilder nameBuilder = new X500NameBuilder();
        nameBuilder.addRDN(BCStyle.CN, "testing");
        org.bouncycastle.asn1.x500.X500Name name = nameBuilder.build();

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        extensionsGenerator.addExtension(
                Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));


        extensionsGenerator.addExtension(
                Extension.extendedKeyUsage,
                true,
                new ExtendedKeyUsage(
                        new KeyPurposeId[] {
                                KeyPurposeId.id_kp_clientAuth,
                                KeyPurposeId.id_kp_serverAuth }
                ));

        GeneralNames subAtlNames = new GeneralNames(
                new GeneralName[]{
                        new GeneralName(GeneralName.dNSName, "test.com"),
                        new GeneralName(GeneralName.iPAddress, TEST_IP_ADDR),
                }
        );
        extensionsGenerator.addExtension(
                Extension.subjectAlternativeName, true, subAtlNames);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(name, keyPair.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PemWriter writer = new PemWriter(new OutputStreamWriter(os, "UTF-8"));
        writer.writeObject(new JcaMiscPEMGenerator(csr));
        writer.flush();

        return os.toByteArray();
    }

    // TODO(mh): Run with a CA container?
    @Ignore
    @Test
    public void testSign() throws Exception {
        DefaultCAClient client = new DefaultCAClient(CA_BASE_URL, createAuthenticatedExecutor());
        X509Certificate certificate = client.sign(createCSR());
        Assert.assertNotNull(certificate);
    }

    @Ignore
    @Test
    public void testBundle() throws Exception {
        DefaultCAClient client = new DefaultCAClient(CA_BASE_URL, createAuthenticatedExecutor());
        X509Certificate certificate = client.sign(createCSR());
        Collection<X509Certificate> certificates = client.chainWithRootCert(certificate);
        Assert.assertTrue(certificates.size() > 0);
    }
}