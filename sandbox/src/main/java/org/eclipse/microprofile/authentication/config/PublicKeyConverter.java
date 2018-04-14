/*
 * Copyright (c) 2016-2017 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.eclipse.microprofile.authentication.config;

import java.security.PublicKey;

import org.eclipse.microprofile.config.spi.Converter;

import static org.eclipse.microprofile.authentication.config.TokenUtils.decodePublicKey;

/**
 * A custom configuration converter for {@linkplain PublicKey} injection using
 * {@linkplain org.eclipse.microprofile.config.inject.ConfigProperty}
 */
public class PublicKeyConverter implements Converter<PublicKey> {
    /**
     * Converts a string to a PublicKey by loading it as a classpath resource
     * @param value - the PEM encoded string value to convert
     * @return the PublicKey loaded as a resource
     * @throws IllegalArgumentException - on failure to load the key
     */
    @Override
    public PublicKey convert(String value) throws IllegalArgumentException {
        PublicKey pk;
        try {
            pk = decodePublicKey(value);
        }
        catch (Exception e) {
            IllegalArgumentException ex = new IllegalArgumentException("Failed to parse: "+value);
            ex.initCause(e);
            throw ex;
        }
        return pk;
    }
}
