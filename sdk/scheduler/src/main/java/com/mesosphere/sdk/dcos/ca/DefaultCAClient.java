package com.mesosphere.sdk.dcos.ca;

import com.mesosphere.sdk.dcos.CertificateAuthorityClient;
import com.mesosphere.sdk.dcos.DcosConstants;
import com.mesosphere.sdk.dcos.http.URLHelper;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import org.apache.http.entity.ContentType;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * A default implementation of {@link CertificateAuthorityClient}.
 */
public class DefaultCAClient implements CertificateAuthorityClient {

    private URL baseURL;
    private Executor httpExecutor;
    private CertificateFactory certificateFactory;

    public DefaultCAClient(URL baseURL, Executor executor) {
        this.baseURL = baseURL;
        this.httpExecutor = executor;

        try {
            this.certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }

    public DefaultCAClient(Executor executor) {
        this(URLHelper.fromUnchecked(DcosConstants.CA_BASE_URI), executor);
    }

    @Override
    public X509Certificate sign(byte[] csr) throws IOException, CertificateException {
        JSONObject data = new JSONObject();
        data.put("certificate_request", new String(csr, Charset.forName("UTF-8")));
        data.put("profile", "");

        Request request = Request.Post(URLHelper.addPathUnchecked(baseURL, "sign").toString())
                .bodyString(data.toString(), ContentType.APPLICATION_JSON);
        Response response = httpExecutor.execute(request);

        String responseContent = response.returnContent().asString();
        data = new JSONObject(responseContent);
        String certificate = data.getJSONObject("result").getString("certificate");

        return (X509Certificate) certificateFactory
                .generateCertificate(
                        new ByteArrayInputStream(certificate.getBytes(Charset.forName("UTF-8"))));
    }

}
