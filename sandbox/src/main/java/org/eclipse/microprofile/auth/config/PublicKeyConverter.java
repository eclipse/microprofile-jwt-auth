package org.eclipse.microprofile.auth.config;

import java.security.PublicKey;

import org.eclipse.microprofile.config.spi.Converter;

import static org.eclipse.microprofile.auth.config.TokenUtils.decodePublicKey;

/**
 * A custom configuration converter for {@linkplain PublicKey} injection using
 * {@linkplain org.eclipse.microprofile.config.inject.ConfigProperty}
 */
public class PublicKeyConverter implements Converter<PublicKey> {
    /**
     * Converts a string to a PublicKey by loading it as a classpath resource
     * @param value - the string value to convert
     * @return the PublicKey loaded as a resource
     * @throws IllegalArgumentException - on failure to load the key
     */
    @Override
    public PublicKey convert(String value) throws IllegalArgumentException {
        PublicKey pk;
        try {
            pk = decodePublicKey(value);
        } catch (Exception e) {
            IllegalArgumentException ex = new IllegalArgumentException("Failed to parse ");
            ex.initCause(e);
            throw ex;
        }
        return pk;
    }
}
