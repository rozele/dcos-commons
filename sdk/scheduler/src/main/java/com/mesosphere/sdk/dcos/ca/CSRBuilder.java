package com.mesosphere.sdk.dcos.ca;


import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs10.PKCS10;
import sun.security.pkcs10.PKCS10Attribute;
import sun.security.x509.*;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.Extension;
import java.util.*;

/**
 * CSRBuilder creates a CSR request that can be signed by CA.
 */
public class CSRBuilder {

    private ArrayList<GeneralNameInterface> sans;
    private HashMap<String, Extension> extensions;
    private X500Name subject;
    private PublicKey publicKey;
    private Signature signature;

    public CSRBuilder(PublicKey publicKey) throws NoSuchAlgorithmException {
        this.publicKey = publicKey;
        this.extensions = new HashMap<>();
        this.sans = new ArrayList<>();
        this.signature = Signature.getInstance("SHA256withRSA");
    }

    public CSRBuilder addSubjectAlternativeName(GeneralNameInterface name) {
        this.sans.add(name);
        return this;
    }

    public CSRBuilder addExtension(String name, Extension extension) {
        this.extensions.put(name, extension);
        return this;
    }

    public CSRBuilder addSubject(X500Name subject) {
        this.subject = subject;
        return this;
    }

    public PKCS10 build() throws NoSuchAlgorithmException, SignatureException, IOException {

        PKCS10 request = new PKCS10(publicKey);

        CertificateExtensions ext = new CertificateExtensions();

        if (!this.sans.isEmpty()) {

            GeneralNames names = new GeneralNames();
            for (GeneralNameInterface san : this.sans) {
                names.add(new GeneralName(san));
            }
            this.addExtension(SubjectAlternativeNameExtension.NAME, new SubjectAlternativeNameExtension(names));

        }

        if (!this.extensions.isEmpty()) {
            for (Map.Entry<String, Extension> entry : this.extensions.entrySet()) {
               ext.set(entry.getKey(), entry.getValue());
            }
        }

        if (!ext.getAllExtensions().isEmpty()) {
            request.getAttributes().setAttribute(X509CertInfo.EXTENSIONS,
                    new PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID, ext));
        }

        return request;

    }

    public PKCS10 buildAndSign(PrivateKey privateKey) throws IOException, InvalidKeyException {

        signature.initSign(privateKey);

        try {
            PKCS10 csr = build();
            csr.encodeAndSign(subject, signature);
            return csr;
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;

    }

}
