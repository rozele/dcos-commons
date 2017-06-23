package com.mesosphere.sdk.dcos.http;

import com.mesosphere.sdk.dcos.auth.TokenProvider;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.protocol.HttpContext;
import org.slf4j.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

public class HttpClientBuilder extends org.apache.http.impl.client.HttpClientBuilder {

    /**
     * Disable TLS verification on built HTTP client.
     * @return
     */
    public HttpClientBuilder disableTLSVerification() {

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

        this
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .setSSLContext(sslContext);

        return this;

    }

    /**
     * Enable authentication token
     * @param provider
     * @return
     */
    public HttpClientBuilder setTokenProvider(TokenProvider provider) {

        this.addInterceptorFirst(new HttpRequestInterceptor() {
            @Override
            public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
                request.addHeader("Authorization", String.format("token=%s", provider.getToken().getValue()));
            }
        });

        return this;

    }


    public HttpClientBuilder setLogger(Logger logger) {

        this.addInterceptorLast(new HttpRequestInterceptor() {
            @Override
            public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
                logger.info(request.toString());
            }
        });

        return this;

    }


    /**
     * Default request connection timeout
     * @param connectionTimeout
     * @return
     */
    public HttpClientBuilder setDefaultConnectionTimeout(int connectionTimeout) {

        RequestConfig requestConfig = RequestConfig
                .custom()
                .setConnectionRequestTimeout(connectionTimeout)
                .build();
        this.setDefaultRequestConfig(requestConfig);

        return this;

    }

}
