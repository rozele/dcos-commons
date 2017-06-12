package com.mesosphere.sdk.dcos.secrets;

import com.google.common.annotations.VisibleForTesting;
import com.mesosphere.sdk.dcos.DcosConstants;
import com.mesosphere.sdk.dcos.SecretsClient;
import org.apache.http.StatusLine;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import org.apache.http.entity.ContentType;
import org.json.JSONObject;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

public class DefaultSecretsClient implements SecretsClient {

    // Each secrets requests is prefixed with secrets store name
    public static final String STORE_PREFIX = "secrets/%s/";

    private URL baseUrl;
    private String store;
    private String token;

    // Executor of HTTP requests, can be overridden mainly for testing purposes.
    private Executor executor;

    public DefaultSecretsClient(URL baseUrl, String token, String store, Executor executor) throws MalformedURLException {
        // TODO(mh): This token is valid only for limited time, it would be better to accept a factory that can
        // fetch and reissue token to be always valid.
        this.token = token;
        this.baseUrl = new URL(baseUrl, String.format(STORE_PREFIX, store));
        this.store = store;
        this.executor = executor;
    }

    public DefaultSecretsClient(URL baseUrl, String token, String store) throws MalformedURLException {
        this(baseUrl, token, store, Executor.newInstance());
    }

    public DefaultSecretsClient(String token, String store) throws MalformedURLException {
        this(new URL(DcosConstants.SECRETS_BASE_URI), token, store);
    }

    public DefaultSecretsClient(String token) throws MalformedURLException {
        this(token, "default");
    }

    @Override
    public void create(String path, Secret secret) throws IOException, SecretsException {
        JSONObject body = secretToJSONObject(secret);
        Request httpRequest = Request.Put(urlForPath(path).toString())
                .bodyString(body.toString(), ContentType.APPLICATION_JSON);
        StatusLine statusLine = executeRequest(httpRequest).returnResponse().getStatusLine();

        handleResponseStatusLine(statusLine, 201, path);
    }

    @Override
    public void delete(String path) throws IOException, SecretsException {
        Request httpRequest = Request.Delete(urlForPath(path).toString());
        StatusLine statusLine = executeRequest(httpRequest).returnResponse().getStatusLine();
        handleResponseStatusLine(statusLine, 204, path);
    }

    @Override
    public void update(String path, Secret secret) throws IOException, SecretsException {
        JSONObject body = secretToJSONObject(secret);
        Request httpRequest = Request.Patch(urlForPath(path).toString())
                .bodyString(body.toString(), ContentType.APPLICATION_JSON);
        StatusLine statusLine = executeRequest(httpRequest).returnResponse().getStatusLine();

        handleResponseStatusLine(statusLine, 204, path);
    }

    @VisibleForTesting
    protected URL urlForPath(String path) throws MalformedURLException {
        if (path.startsWith("/")) {
            path = path.substring(1);
        }

        return new URL(this.baseUrl, path);
    }

    protected Response executeRequest(Request request) throws IOException {
        request = request.addHeader("Authorization", String.format("token=%s", this.token));
        return executor.execute(request);
    }

    protected JSONObject secretToJSONObject(Secret secret) {
        JSONObject body = new JSONObject();
        body.put("value", secret.getValue());
        body.put("author", secret.getAuthor());
        body.put("created", secret.getCreated());
        body.put("description", secret.getDescription());
        body.put("labels", secret.getLabels());
        return body;
    }

    /**
     * Handle common responses from different API endpoints of DC/OS secrets service.
     * @param statusLine
     * @param okCode
     * @param path
     * @throws SecretsException
     */
    protected void handleResponseStatusLine(StatusLine statusLine, int okCode, String path) throws SecretsException {
        if (statusLine.getStatusCode() == okCode) {
            return;
        }

        if (statusLine.getStatusCode() == 403) {
            throw new ForbiddenException(this.store, path);
        }

        if (statusLine.getStatusCode() == 404) {
            throw new NotFoundException();
        }

        if (statusLine.getStatusCode() == 409) {
            throw new AlreadyExistsException();
        }

        // Unhandled HTTP code
        throw new SecretsException();
    }

    @VisibleForTesting
    protected void setExecutor(Executor executor) {
        this.executor = executor;
    }
}
