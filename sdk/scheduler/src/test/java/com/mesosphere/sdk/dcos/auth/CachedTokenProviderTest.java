package com.mesosphere.sdk.dcos.auth;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CachedTokenProviderTest {

    @Mock private Token mockToken;
    @Mock private TokenProvider mockProvider;

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetTokenRetrieval() throws IOException {
        when(mockToken.getExpiration()).thenReturn(
                Date.from(Instant.now().plusSeconds(60)));
        when(mockProvider.getToken()).thenReturn(mockToken);

        CachedTokenProvider cachedTokenProvider = new CachedTokenProvider(mockProvider);
        Assert.assertEquals(cachedTokenProvider.getToken(), mockToken);

        verify(mockProvider, times(1)).getToken();
    }

    @Test
    public void testGetTokenIsCached() throws IOException {
        when(mockToken.getExpiration()).thenReturn(
                Date.from(Instant.now().plusSeconds(60)));
        when(mockProvider.getToken()).thenReturn(mockToken);

        CachedTokenProvider cachedTokenProvider = new CachedTokenProvider(mockProvider);
        cachedTokenProvider.getToken();
        // Second call should be cached
        cachedTokenProvider.getToken();

        verify(mockToken, times(1)).getExpiration();
        verify(mockProvider, times(1)).getToken();
    }

    @Test
    public void testExpiredTokenIsRefreshed() throws IOException {
        // Create token that expired 60 seconds ago
        when(mockToken.getExpiration()).thenReturn(
                Date.from(Instant.now().minusSeconds(60)));
        when(mockProvider.getToken()).thenReturn(mockToken);

        CachedTokenProvider cachedTokenProvider = new CachedTokenProvider(mockProvider);
        cachedTokenProvider.getToken();
        // Second call should be cached
        cachedTokenProvider.getToken();

        verify(mockToken, times(1)).getExpiration();
        verify(mockProvider, times(2)).getToken();
    }

}