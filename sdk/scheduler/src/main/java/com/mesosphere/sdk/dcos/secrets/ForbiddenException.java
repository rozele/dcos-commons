package com.mesosphere.sdk.dcos.secrets;

/**
 * Exception representing permission error.
 */
public class ForbiddenException extends SecretsException {

    public ForbiddenException(String message, String store, String path) {
        super(message, store, path);
    }

    public ForbiddenException(String message, Throwable cause, String store, String path) {
        super(message, cause, store, path);
    }

    /**
     * @return A string representing DC/OS permission required to operate on given secret.
     */
    public String getMissingPermission() {
        return String.format("dcos:secrets:%s:%s", getStore(), getPath());
    }
}
