package com.mesosphere.sdk.dcos.ca;

import com.mesosphere.sdk.dcos.http.HttpClientBuilder;
import com.mesosphere.sdk.dcos.auth.StaticTokenProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.fluent.Executor;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import sun.security.pkcs10.PKCS10;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.DNSName;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.X500Name;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Vector;

public class DefaultCAClientTest {

    private String TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiJhZG1pbiIsImV4cCI6MTQ5ODMxMjQzOH0.A7qDzH6rzNuV3UP5TF8rsTNk2EhfOByhicv7IsBPPk_WhlO3FWP5wSPdsu8I_nGrP1-TVHqtJWlBqseXvai4_80DlJPNqrsWWkgYr8-OOpGMDEpll2AmjRyFEizxBI1xw8CZ12ZVM3NwlfCWe-yCmBfaFx0OmEZEANAvNP8RPDuqWHmfBFdcR7WHLhYpdMZ2iDtquy-dEcZuxYptJWn-8Pt1YzF4u7p82cILDKe6rCwZUso4DBnkRnjqL7ntlfXN_M8zjV9k65mbqmZXjejJZT7mJnnYoumrtPg46Kg85lHB-xhDrJp9_D7iMKSbxCaaw6Gk3q-puw0M-jQ-T_ASnA";

    private KeyPairGenerator KEY_PAIR_GENERATOR;
    private int RSA_KEY_SIZE = 2048;

    private URL CA_BASE_URL;

    @Before
    public void init() throws NoSuchAlgorithmException, MalformedURLException {
        KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("RSA");
        KEY_PAIR_GENERATOR.initialize(RSA_KEY_SIZE);
        CA_BASE_URL = new URL("https://172.17.0.2/ca/api/v2/");
    }

    public Executor createAuthenticatedExecutor() {

        HttpClient httpClient = new HttpClientBuilder()
                .disableTLSVerification()
                .setTokenProvider(new StaticTokenProvider(TOKEN))
                .build();
        return Executor.newInstance(httpClient);

    }

    // TODO(mh): Run with a CA container?
    @Ignore
    @Test
    public void testSign() throws Exception {
        DefaultCAClient client = new DefaultCAClient(CA_BASE_URL, createAuthenticatedExecutor());

        KeyUsageExtension keyUsage = new KeyUsageExtension();
        keyUsage.set(KeyUsageExtension.DIGITAL_SIGNATURE, true);

        int[] serverAuthOidData = new int[]{1, 3, 6, 1, 5, 5, 7, 3, 1};
        int[] clientAuthOidData = new int[]{1, 3, 6, 1, 5, 5, 7, 3, 2};
        Vector<ObjectIdentifier> extendedKeyUsages = new Vector<>(Arrays.asList(
                new ObjectIdentifier(clientAuthOidData),
                new ObjectIdentifier(serverAuthOidData)
        ));
        ExtendedKeyUsageExtension extendedKeyUsage = new ExtendedKeyUsageExtension(
                extendedKeyUsages);

        KeyPair keyPair = KEY_PAIR_GENERATOR.generateKeyPair();

        PKCS10 csr = new CSRBuilder(keyPair.getPublic())
                .addSubject(new X500Name("CN=martin"))
                .addSubjectAlternativeName(new DNSName("test.com"))
                .addExtension(KeyUsageExtension.NAME, keyUsage)
                .addExtension(ExtendedKeyUsageExtension.NAME, extendedKeyUsage)
                .buildAndSign(keyPair.getPrivate());

        // Encode it to PEM format
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(os);
        csr.print(ps);

        X509Certificate certificate = client.sign(os.toByteArray());
        Assert.assertNotNull(certificate);
    }
}