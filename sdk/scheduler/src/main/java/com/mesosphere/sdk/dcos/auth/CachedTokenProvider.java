package com.mesosphere.sdk.dcos.auth;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

/**
 * CachedTokenProvider retrieves token from underlying provider and caches the value. It automatically triggers
 * getToken() method on underlying provider when token is about to expire.
 *
 * // TODO(mh): This could be also running in a separate thread in background.
 * // TODO(mh): Does this needs to be threadsafe?
 */
public class CachedTokenProvider implements TokenProvider {

    private TokenProvider provider;
    private Optional<Token> token;
    private int triggerRefreshBeforeSeconds;

    public CachedTokenProvider(TokenProvider provider, int triggerRefreshBeforeSeconds) {
        this.provider = provider;
        this.triggerRefreshBeforeSeconds = triggerRefreshBeforeSeconds;
        this.token = Optional.empty();
    }

    public CachedTokenProvider(TokenProvider provider) {
        this(provider, 30);
    }

    @Override
    public Token getToken() throws IOException {

        if (token.isPresent()) {

            Instant triggerRefresh = token.get()
                    .getExpiration()
                    .toInstant()
                    .minusSeconds(this.triggerRefreshBeforeSeconds);

            if (triggerRefresh.isAfter(Instant.now())) {
                return token.get();
            }

        }

        token = Optional.of(this.provider.getToken());
        return token.get();
    }
}
