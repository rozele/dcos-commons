package com.mesosphere.sdk.dcos.http;

import com.mesosphere.sdk.dcos.DcosConstants;
import org.junit.Assert;
import org.junit.Test;

import java.net.URL;

public class URLHelperTest {

    @Test
    public void addPathWithPrefix() throws Exception {
        URL base = URLHelper.fromUnchecked(DcosConstants.CA_BASE_URI);
        String path = URLHelper.addPathUnchecked(base, "/sign").getPath();
        Assert.assertEquals(path, "/ca/api/v2/sign");
    }

}