package com.mesosphere.sdk.specification;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.mesosphere.sdk.specification.validation.ValidationUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;

import javax.validation.Valid;

/**
 * Default implementation of {@link TransportEncryptionSpec}.
 */
public class DefaultTransportEncryptionSpec implements TransportEncryptionSpec {

    @Valid
    private String name;

    @Valid
    private Type type;

    @JsonCreator
    public DefaultTransportEncryptionSpec(
            @JsonProperty("name") String name,
            @JsonProperty("type") Type type) {
        this.name = name;
        this.type = type;
    }

    public DefaultTransportEncryptionSpec(Builder builder) {
        this(builder.name, builder.type);
        ValidationUtils.validate(this);
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Type getType() {
        return type;
    }

    @Override
    public boolean equals(Object o) {
        return EqualsBuilder.reflectionEquals(this, o);
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
    public String toString() {
        return ReflectionToStringBuilder.toString(this);
    }

    public static final class Builder {
        private String name;
        private Type type;

        private Builder() {}

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder type(Type type) {
            this.type = type;
            return this;
        }

        public DefaultTransportEncryptionSpec build() {
            return new DefaultTransportEncryptionSpec(this);
        }
    }
}
