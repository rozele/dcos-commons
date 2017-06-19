package com.mesosphere.sdk.dcos.http;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * URLHelper for easier URL building.
 */
public class URLHelper {

    public static URL fromUnchecked(String url) {

        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        return null;

    }

    public static URL addPathUnchecked(URL base, String path) {

        try {
            return addPath(base, path);
        } catch (MalformedURLException e) {
            e.printStackTrace();
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
