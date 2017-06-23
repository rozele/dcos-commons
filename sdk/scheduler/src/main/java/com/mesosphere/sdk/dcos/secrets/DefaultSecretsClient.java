package com.mesosphere.sdk.dcos.secrets;

import com.google.common.annotations.VisibleForTesting;
import com.mesosphere.sdk.dcos.DcosConstants;
import com.mesosphere.sdk.dcos.SecretsClient;
import com.mesosphere.sdk.dcos.http.URLHelper;
import org.apache.http.StatusLine;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URL;

public class DefaultSecretsClient implements SecretsClient {

    // Each secrets requests is prefixed with secrets store name
    public static final String STORE_PREFIX = "secret/%s/";

    private URL baseUrl;
    private String store;
    private Executor httpExecutor;

    public DefaultSecretsClient(URL baseUrl, String store, Executor executor) {
        this.baseUrl = URLHelper.addPathUnchecked(baseUrl, String.format(STORE_PREFIX, store));
        this.store = store;
        this.httpExecutor = executor;
    }

    public DefaultSecretsClient(String store, Executor executor) {
        this(URLHelper.fromUnchecked(DcosConstants.SECRETS_BASE_URI), store, executor);
    }

    public DefaultSecretsClient(Executor executor) {
        this("default", executor);
    }

    @Override
    public void create(String path, Secret secret) throws IOException, SecretsException {
        JSONObject body = secretToJSONObject(secret);
        Request httpRequest = Request.Put(urlForPath(path).toString())
                .bodyString(body.toString(), ContentType.APPLICATION_JSON);
        StatusLine statusLine = httpExecutor.execute(httpRequest).returnResponse().getStatusLine();

        handleResponseStatusLine(statusLine, 201, path);
    }

    @Override
    public void delete(String path) throws IOException, SecretsException {
        Request httpRequest = Request.Delete(urlForPath(path).toString());
        StatusLine statusLine = httpExecutor.execute(httpRequest).returnResponse().getStatusLine();
        handleResponseStatusLine(statusLine, 204, path);
    }

    @Override
    public void update(String path, Secret secret) throws IOException, SecretsException {
        JSONObject body = secretToJSONObject(secret);
        Request httpRequest = Request.Patch(urlForPath(path).toString())
                .bodyString(body.toString(), ContentType.APPLICATION_JSON);
        StatusLine statusLine = httpExecutor.execute(httpRequest).returnResponse().getStatusLine();

        handleResponseStatusLine(statusLine, 204, path);
    }

    @VisibleForTesting
    protected URL urlForPath(String path) {
        return URLHelper.addPathUnchecked(baseUrl, path);
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
            throw new ForbiddenException(store, path);
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

}
