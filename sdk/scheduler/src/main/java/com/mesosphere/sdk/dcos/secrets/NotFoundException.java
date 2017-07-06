package com.mesosphere.sdk.dcos.secrets;

/**
 * An operation requires existing secret which wasn't found.
 */
public class NotFoundException extends SecretsException {
    public NotFoundException(String message, String store, String path) {
        super(message, store, path);
    }

    public NotFoundException(String message, Throwable cause, String store, String path) {
        super(message, cause, store, path);
    }
}
