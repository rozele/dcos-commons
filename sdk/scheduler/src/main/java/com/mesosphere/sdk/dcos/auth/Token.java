package com.mesosphere.sdk.dcos.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;

/**
 * Token represents a JWT authentication token issued by DC/OS Bouncer IAM service.
 */
public class Token {

    private final DecodedJWT token;

    public Token(String value) {
        this.token = JWT.decode(value);
    }

    public Date getExpiration() {
        return this.token.getExpiresAt();
    }

    public String getValue() {
        return this.token.getToken();
    }

}
