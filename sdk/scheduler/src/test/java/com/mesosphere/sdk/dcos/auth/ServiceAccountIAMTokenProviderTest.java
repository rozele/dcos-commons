package com.mesosphere.sdk.dcos.auth;


import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ServiceAccountIAMTokenProviderTest {

    private KeyFactory KEY_FACTORY;

    private String TEST_SERVICE_ACCOUNT = "test_service";

    @Before
    public void init() throws NoSuchAlgorithmException {
        KEY_FACTORY = KeyFactory.getInstance("RSA");
    }

    private KeyPair loadRSAKeyPair() throws IOException, InvalidKeySpecException {
        ClassLoader classLoader = getClass().getClassLoader();

        File privateKeyFile = new File(classLoader.getResource("rsa-private-key.pem").getFile());
        File publicKeyFile = new File(classLoader.getResource("rsa-public-key.pem").getFile());

        String privateKeyStr = new String(Files.readAllBytes(Paths.get(privateKeyFile.getPath())))
                .replaceAll("-----BEGIN (.* )?PRIVATE KEY-----\n", "")
                .replaceAll("-----END (.* )?PRIVATE KEY-----\n?", "")
                .replaceAll("\n", "");
        byte[] privateKeyBytes  = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = KEY_FACTORY.generatePrivate(spec);

        String publicKeyStr = new String(Files.readAllBytes(Paths.get(publicKeyFile.getPath())))
                .replaceAll("-----BEGIN (.* )?PUBLIC KEY-----\n", "")
                .replaceAll("-----END (.* )?PUBLIC KEY-----\n?", "")
                .replaceAll("\n", "");
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = KEY_FACTORY.generatePublic(publicKeySpec);

        return new KeyPair(publicKey, privateKey);
    }

    // Following tests expects DC/OS to be running on 172.17.0.2 IP address and its not ran by default.
    // To get this test passing the bouncer running on 172.17.0.2 needs to be configured with service account
    // with uid: "test_service" and private key found in resources/rsa-private-key.pem
    // TODO(mh): Maybe we could run a bouncer in the docker container?
    @Ignore
    @Test
    public void testGetTokenAgainstRunningBouncer() throws IOException, InvalidKeySpecException {

        KeyPair keyPair = loadRSAKeyPair();

        ServiceAccountIAMTokenProvider provider = new ServiceAccountIAMTokenProvider.Builder()
                .setIamUrl(new URL("https://172.17.0.2/acs/api/v1/auth/login"))
                .setUid(TEST_SERVICE_ACCOUNT)
                .setPrivateKey((RSAPrivateKey) keyPair.getPrivate())
                .setDisableTLSVerification(true)
                .build();
        Token token = provider.getToken();

        Assert.assertTrue(token.getValue().length() > 0);

    }

}