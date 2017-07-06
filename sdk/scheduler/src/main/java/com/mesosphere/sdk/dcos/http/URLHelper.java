package com.mesosphere.sdk.dcos.http;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * URLHelper for easier URL building.
 */
public class URLHelper {

    private static final Logger logger = LoggerFactory.getLogger(URLHelper.class);

    public static URL fromUnchecked(String url) {
        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            logger.error("Failed to create URL from string", e);
        }
        return null;
    }

    public static URL addPathUnchecked(URL base, String path) {
        try {
            return addPath(base, path);
        } catch (MalformedURLException e) {
            logger.error("Failed to add path to the URL", e);
        }
        return null;
    }

    public static URL addPath(URL base, String path) throws MalformedURLException {
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        return new URL(base, path);
    }

}
