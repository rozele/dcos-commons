package com.mesosphere.sdk.dcos.auth;

import java.io.IOException;

/**
 * TokenProvider describes an interface that provides valid DC/OS auth token.
 */
public interface TokenProvider {

    public Token getToken() throws IOException;

}
