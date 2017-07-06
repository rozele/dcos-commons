package com.mesosphere.sdk.dcos.auth;

/**
 * Constant Token Provider always returns single pre-configured auth token. It can be used for testing and for known
 * life of configured token.
 */
public class ConstantTokenProvider implements TokenProvider {

    private final Token token;

    public ConstantTokenProvider(String token) {
        this.token = new Token(token);
    }

    @Override
    public Token getToken() {
       return this.token;
    }

}
