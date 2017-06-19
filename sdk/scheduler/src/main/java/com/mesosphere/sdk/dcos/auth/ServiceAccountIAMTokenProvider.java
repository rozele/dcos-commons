package com.mesosphere.sdk.dcos.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.mesosphere.sdk.dcos.HttpClientBuilder;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import org.apache.http.entity.ContentType;
import org.json.JSONObject;

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
 *
 * For reference implementation
 * @see "https://github.com/mesosphere/bouncer/blob/fc4e0f4205112f3a9bc2b10bb4639d9985beb19e/lynch/lynch/auth.py#L63"
 */
public class ServiceAccountIAMTokenProvider implements TokenProvider {

    private URL iamUrl;
    private String uid;
    private RSAPrivateKey privateKey;
    private Executor httpExecutor;

    public ServiceAccountIAMTokenProvider(
            URL iamUrl,
            String uid,
            RSAPrivateKey privateKey,
            Executor executor) {
        this.iamUrl = iamUrl;
        this.uid = uid;
        this.privateKey = privateKey;
        this.httpExecutor = executor;
    }

    public ServiceAccountIAMTokenProvider(Builder builder) {
        this(
                builder.iamUrl,
                builder.uid,
                builder.privateKey,
                builder.buildExecutor()
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

        Request request = Request.Post(iamUrl.toString())
                .bodyString(data.toString(), ContentType.APPLICATION_JSON);

        Response response = httpExecutor.execute(request);

        JSONObject resposneData = new JSONObject(response.returnContent().asString());
        return new Token(resposneData.getString("token"));
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
