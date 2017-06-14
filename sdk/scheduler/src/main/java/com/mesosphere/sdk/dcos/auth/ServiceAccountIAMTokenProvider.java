package com.mesosphere.sdk.dcos.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.apache.http.client.HttpClient;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONObject;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Provides a token retrieved by `login` operation against IAM service with given service account.
 *
 * For reference implementation
 * @see https://github.com/mesosphere/bouncer/blob/fc4e0f4205112f3a9bc2b10bb4639d9985beb19e/lynch/lynch/auth.py#L63
 */
public class ServiceAccountIAMTokenProvider implements TokenProvider {

    private URL iamUrl;
    private String uid;
    private RSAPrivateKey privateKey;
    private boolean disableTLSVerification;
    private final long connectionTimeoutMs;

    public ServiceAccountIAMTokenProvider(
            URL iamUrl, String uid, RSAPrivateKey privateKey, boolean disableTLSVerification, long connectionTimeoutMs) {
        this.iamUrl = iamUrl;
        this.uid = uid;
        this.privateKey = privateKey;
        this.disableTLSVerification = disableTLSVerification;
        this.connectionTimeoutMs = connectionTimeoutMs;
    }

    public ServiceAccountIAMTokenProvider(Builder builder) {
        this(
                builder.iamUrl,
                builder.uid,
                builder.privateKey,
                builder.disableTLSVerification,
                builder.connectionTimeoutMs
        );
    }

    @Override
    public Token getToken() throws IOException {
        String serviceLoginToken = null;
        try {
            serviceLoginToken = JWT.create()
                    .withClaim("uid", uid)
                    .withExpiresAt(Date.from(Instant.now().plusSeconds(120)))
                    .sign(getRSA256Algorithm());
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        JSONObject data = new JSONObject();
        data.put("uid", uid);
        data.put("token", serviceLoginToken);

        Executor executor = Executor.newInstance(createHttpClient());
        Request request = Request.Post(iamUrl.toString())
                .bodyString(data.toString(), ContentType.APPLICATION_JSON);
        Response response = executor.execute(request);

        JSONObject resposneData = new JSONObject(response.returnContent().asString());
        return new Token(resposneData.getString("token"));
    }

    // TODO(mh): Extract this to common base class or static class that can be used across different
    //           service consumers.
    private HttpClient createHttpClient() {
        HttpClientBuilder builder = HttpClients.custom();

        if (this.disableTLSVerification) {
            TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }

            }};

            SSLContext sslContext = null;
            try {
                sslContext = SSLContext.getInstance("TLS");
            } catch (NoSuchAlgorithmException e) {
            }

            try {
                sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }
            builder
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .setSSLContext(sslContext);
        }

        builder.setConnectionTimeToLive(connectionTimeoutMs, TimeUnit.MILLISECONDS);

        return builder.build();
    }

    /**
     * Creates RS256 JWT Algorithm for signing tokens.
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    private Algorithm getRSA256Algorithm() throws InvalidKeySpecException, NoSuchAlgorithmException {
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPrivateExponent());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return Algorithm.RSA256((RSAPublicKey) publicKey, privateKey);
    }

    public static class Builder {
        private URL iamUrl;
        private String uid;
        private RSAPrivateKey privateKey;
        private boolean disableTLSVerification;
        private long connectionTimeoutMs;

        public Builder() {
            this.disableTLSVerification = false;
            this.connectionTimeoutMs = 5*1000;
        }

        public Builder setIamUrl(URL iamUrl) {
            this.iamUrl = iamUrl;
            return this;
        }

        public Builder setUid(String uid) {
            this.uid = uid;
            return this;
        }

        public Builder setPrivateKey(RSAPrivateKey privateKey) {
            this.privateKey = privateKey;
            return this;
        }

        public Builder setDisableTLSVerification(boolean disableTLSVerification) {
            this.disableTLSVerification = disableTLSVerification;
            return this;
        }

        public Builder setConnectionTimeoutMs(long connectionTimeoutMs) {
            this.connectionTimeoutMs = connectionTimeoutMs;
            return this;
        }

        public ServiceAccountIAMTokenProvider build() {
            return new ServiceAccountIAMTokenProvider(this);
        }
    }
}
