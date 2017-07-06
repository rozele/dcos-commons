package com.mesosphere.sdk.dcos.secrets;

/**
 * An operation is attempting to create a secret that already exists.
 */
public class AlreadyExistsException extends SecretsException {
    public AlreadyExistsException(String message, String store, String path) {
        super(message, store, path);
    }
}
