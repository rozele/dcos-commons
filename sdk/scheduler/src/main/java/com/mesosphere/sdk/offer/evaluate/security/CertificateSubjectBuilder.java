package com.mesosphere.sdk.offer.evaluate.security;

import com.mesosphere.sdk.specification.validation.ValidationUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import javax.validation.Valid;

/**
 * A {@link CertificateSubjectBuilder} provides easy way to generate X500 name.
 */
public class CertificateSubjectBuilder {

    @Valid
    private String countryName;
    @Valid
    private String stateOrProvinceName;
    @Valid
    private String localityName;
    @Valid
    private String organizationName;
    @Valid
    private String commonName;

    public CertificateSubjectBuilder() {
        countryName = "US";
        stateOrProvinceName = "CA";
        localityName = "San Francisco";
        organizationName = "Mesosphere, Inc";
    }

    public CertificateSubjectBuilder setCountryName(String countryName) {
        this.countryName = countryName;
        return this;
    }

    public CertificateSubjectBuilder setStateOrProvinceName(String stateOrProvinceName) {
        this.stateOrProvinceName = stateOrProvinceName;
        return this;
    }

    public CertificateSubjectBuilder setLocalityName(String localityName) {
        this.localityName = localityName;
        return this;
    }

    public CertificateSubjectBuilder setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
        return this;
    }

    public CertificateSubjectBuilder setCommonName(String commonName) {
        this.commonName = commonName;
        return this;
    }

    public X500Name build() {
        ValidationUtils.validate(this);
        return new X500NameBuilder()
                .addRDN(BCStyle.CN, commonName)
                .addRDN(BCStyle.O, organizationName)
                .addRDN(BCStyle.L, localityName)
                .addRDN(BCStyle.ST, stateOrProvinceName)
                .addRDN(BCStyle.C, countryName)
                .build();
    }

}
