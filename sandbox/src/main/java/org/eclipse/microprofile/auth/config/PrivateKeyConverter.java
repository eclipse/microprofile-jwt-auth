package org.eclipse.microprofile.auth.config;

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
import java.security.PrivateKey;

import org.eclipse.microprofile.config.spi.Converter;

import static org.eclipse.microprofile.auth.config.TokenUtils.decodePrivateKey;

/**
 * A custom configuration converter for {@linkplain PrivateKey} injection using
 * {@linkplain org.eclipse.microprofile.config.inject.ConfigProperty}
 */
public class PrivateKeyConverter implements Converter<PrivateKey> {
    /**
     * Converts a string to a PrivateKey by loading it as a classpath resource
     * @param value - the string value to convert
     * @return the PrivateKey loaded as a resource
     * @throws IllegalArgumentException - on failure to load the key
     */
    @Override
    public PrivateKey convert(String value) throws IllegalArgumentException {

        PrivateKey pk = null;
        try {
            pk = decodePrivateKey(value);
        }
        catch (Exception e) {
            IllegalArgumentException ex = new IllegalArgumentException("Failed to parse ");
            ex.initCause(e);
            throw ex;
        }
        return pk;
    }
}
