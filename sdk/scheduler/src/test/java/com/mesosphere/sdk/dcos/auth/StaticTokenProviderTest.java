package com.mesosphere.sdk.dcos.auth;

import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class StaticTokenProviderTest {

    @Test
    public void testToken() throws IOException {
        TokenProvider tokenProvider = new StaticTokenProvider("test-token");
        Assert.assertEquals(tokenProvider.getToken().getValue(), "test-token");
    }

}
