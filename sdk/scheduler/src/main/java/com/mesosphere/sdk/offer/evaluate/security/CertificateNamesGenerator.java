package com.mesosphere.sdk.offer.evaluate.security;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 * A {@link CertificateNamesGenerator} creates relevant names for given service pod.
 *
 * // TODO(mh): What about IP per container feature??
 */
public class CertificateNamesGenerator {

    private String serviceName;

    public CertificateNamesGenerator(String serviceName) {
        this.serviceName = serviceName;
    }

    /**
     * Returns a Subject for service certificate.
     * @return
     */
    public X500Name getSubject() {
       // TODO(mh): Should we somehow improve certificate name here? Right now it reflects only service
       //           name. Should we somehow add pod name and requested certificate name?
       return new CertificateSubjectBuilder()
                .setCommonName(serviceName)
                .build();
    }

    /**
     * Returns additional Subject Alternative Names for service certificates.
     * @return
     */
    public GeneralNames getSANs() {
        // TODO(mh): Should we dynamically test whether the network is overlay? If the network isn't
        // overlay there is no vipName available.
        String vipName = String.format("*.%s.autoip.dcos.thisdcos.directory", serviceName);

        GeneralNames subAtlNames = new GeneralNames(
                new GeneralName[]{
                        new GeneralName(GeneralName.dNSName, vipName),
                }
        );

        return subAtlNames;
    }

}
