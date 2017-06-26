package com.mesosphere.sdk.dcos.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.mesosphere.sdk.dcos.http.HttpClientBuilder;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import org.apache.http.entity.ContentType;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Date;

/**
 * Provides a token retrieved by `login` operation against IAM service with given service account.
 */
public class ServiceAccountIAMTokenProvider implements TokenProvider {

    private URL iamUrl;
    private String uid;
    private RSAPrivateKey privateKey;
    private Executor httpExecutor;

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private ServiceAccountIAMTokenProvider(
            URL iamUrl,
            String uid,
            RSAPrivateKey privateKey,
            Executor executor) {
        this.iamUrl = iamUrl;
        this.uid = uid;
        this.privateKey = privateKey;
        this.httpExecutor = executor;
    }

    private ServiceAccountIAMTokenProvider(Builder builder) {
        this(
                builder.iamUrl,
                builder.uid,
                builder.privateKey,
                builder.buildExecutor()
        );
    }

    @Override
    public Token getToken() throws IOException {
        String serviceLoginToken = JWT.create()
                    .withClaim("uid", uid)
                    .withExpiresAt(Date.from(Instant.now().plusSeconds(120)))
                    .sign(getRSA256Algorithm());

        JSONObject data = new JSONObject();
        data.put("uid", uid);
        data.put("token", serviceLoginToken);

        Request request = Request.Post(iamUrl.toString())
                .bodyString(data.toString(), ContentType.APPLICATION_JSON);

        Response response = httpExecutor.execute(request);

        JSONObject responseData = new JSONObject(response.returnContent().asString());
        return new Token(responseData.getString("token"));
    }

    /**
     * Creates RS256 JWT Algorithm for signing tokens.
     * @return
     */
    private Algorithm getRSA256Algorithm() {
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPrivateExponent());

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to create KeyFactory", e);
            e.printStackTrace();
        }

        PublicKey publicKey = null;
        try {
            publicKey = keyFactory.generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            logger.error("Failed to generate public key from private key spec", e);
        }

        return Algorithm.RSA256((RSAPublicKey) publicKey, privateKey);
    }

    /**
     * A {@link ServiceAccountIAMTokenProvider} class builder.
     */
    public static class Builder {
        private URL iamUrl;
        private String uid;
        private RSAPrivateKey privateKey;
        private boolean disableTLSVerification;
        private int connectionTimeout;

        public Builder() {
            this.disableTLSVerification = false;
            this.connectionTimeout = 5;
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

        public Builder setConnectionTimeout(int connectionTimeout) {
            this.connectionTimeout = connectionTimeout;
            return this;
        }

        public Executor buildExecutor() {
            HttpClientBuilder httpClientBuilder = new HttpClientBuilder();

            if (disableTLSVerification) {
                httpClientBuilder.disableTLSVerification();
            }

            if (connectionTimeout > 0) {
                httpClientBuilder.setDefaultConnectionTimeout(connectionTimeout);
            }

            return Executor.newInstance(httpClientBuilder.build());
        }

        public ServiceAccountIAMTokenProvider build() {
            return new ServiceAccountIAMTokenProvider(this);
        }
    }
}
