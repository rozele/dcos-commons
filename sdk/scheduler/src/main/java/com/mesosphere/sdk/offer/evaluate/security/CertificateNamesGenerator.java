package com.mesosphere.sdk.offer.evaluate.security;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 * A {@link CertificateNamesGenerator} creates relevant names for given service pod.
 */
public class CertificateNamesGenerator {

    private String serviceName;
    private String taskName;

    public CertificateNamesGenerator(String serviceName, String taskName) {
        this.serviceName = serviceName;
        this.taskName = taskName;
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
        String vipWildcardName = String.format("*.%s.autoip.dcos.thisdcos.directory", serviceName);
        String vipTaskName = String.format("%s.%s.autoip.dcos.thisdcos.directory", taskName, serviceName);

        GeneralNames subAtlNames = new GeneralNames(
                new GeneralName[]{
                        new GeneralName(GeneralName.dNSName, vipTaskName),
                        new GeneralName(GeneralName.dNSName, vipWildcardName),
                }
        );

        return subAtlNames;
    }

}
