package com.mesosphere.sdk.dcos.auth;

/**
 * Static Token Provider always returns single pre-configured auth token. It can be used for testing and for known
 * life of configured token.
 */
public class StaticTokenProvider implements TokenProvider {

    private Token token;

    public StaticTokenProvider(String token) {
        this.token = new Token(token);
    }

    @Override
    public Token getToken() {
       return this.token;
    }

}
