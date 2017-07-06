package com.mesosphere.sdk.dcos.auth;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

/**
 * CachedTokenProvider retrieves token from underlying provider and caches the value. It automatically triggers
 * getToken() method on underlying provider when token is about to expire.
 */
public class CachedTokenProvider implements TokenProvider {

    private final TokenProvider provider;
    private Optional<Token> token;
    private final int ttlSeconds;

    public CachedTokenProvider(TokenProvider provider, int ttlSeconds) {
        this.provider = provider;
        this.ttlSeconds = ttlSeconds;
        this.token = Optional.empty();
    }

    public CachedTokenProvider(TokenProvider provider) {
        this(provider, 30);
    }

    @Override
    public synchronized Token getToken() throws IOException {
        if (token.isPresent()) {

            Instant triggerRefresh = token.get()
                    .getExpiration()
                    .toInstant()
                    .minusSeconds(this.ttlSeconds);

            if (triggerRefresh.isAfter(Instant.now())) {
                return token.get();
            }

        }

        token = Optional.of(this.provider.getToken());
        return token.get();
    }
}
