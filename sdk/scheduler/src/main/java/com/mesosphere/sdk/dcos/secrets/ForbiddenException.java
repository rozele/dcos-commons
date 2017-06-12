package com.mesosphere.sdk.dcos.secrets;

/**
 * Exception representing permission error.
 */
public class ForbiddenException extends SecretsException {
    private String store;
    private String path;

    public ForbiddenException(String store, String path) {
        this.store = store;
        this.path = path;
    }

    /**
     * @return A string representing DC/OS permission required to operate on given secret.
     */
    public String getMissingPermission() {
        return String.format("dcos:secrets:%s:%s", store, path);
    }
}
