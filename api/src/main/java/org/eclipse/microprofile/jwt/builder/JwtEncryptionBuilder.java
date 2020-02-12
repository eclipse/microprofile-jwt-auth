/*
 * Copyright (c) 2020 Contributors to the Eclipse Foundation
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
package org.eclipse.microprofile.jwt.builder;

import org.eclipse.microprofile.jwt.algorithm.ContentEncryptionAlgorithm;
import org.eclipse.microprofile.jwt.algorithm.KeyEncryptionAlgorithm;

/**
 * JWT JsonWebEncryption Builder.
 * 
 * <p>
 * JwtEncryptionBuilder implementations must set the 'alg' (key management algorithm) header to 'RSA-OAEP'
 * and 'enc' (content encryption algorithm) header to 'A256GCM' unless they have already been set.
 * The 'cty' (content type) header must be set to 'JWT' when the inner signed JWT is encrypted.
 * <p>
 * Note that JwtEncryptionBuilder implementations are not expected to be thread-safe.
 * 
 * @see <a href="https://tools.ietf.org/html/rfc7516">RFC7516</a>
 */
public interface JwtEncryptionBuilder extends JwtEncryption {

    /**
     * Set an 'alg' key encryption algorithm.
     * Note that only the 'RSA-OAEP' algorithm must be supported.
     * A key of size 2048 bits or larger MUST be used with the 'RSA-OAEP' algorithm.
     * 
     * @param algorithm the key encryption algorithm
     * @return JwtEncryptionBuilder
     */
    JwtEncryptionBuilder keyEncryptionAlgorithm(KeyEncryptionAlgorithm algorithm);

    /**
     * Set an 'enc' content encryption algorithm.
     * Note that only the 'A256GCM' algorithm must be supported.
     * 
     * @param algorithm the content encryption algorithm
     * @return JwtEncryptionBuilder
     */
    JwtEncryptionBuilder contentEncryptionAlgorithm(ContentEncryptionAlgorithm algorithm);

    /**
     * Set a 'kid' key encryption key id.
     * 
     * @param keyId the key id
     * @return JwtEncryptionBuilder
     */
    JwtEncryptionBuilder keyEncryptionKeyId(String keyId);

    /**
     * Custom JWT encryption header.
     * 
     * Supporting the 'alg' key encryption and 'enc' content encryption algorithms not matching one of
     * the {@link KeyEncryptionAlgorithm} and {@link ContentEncryptionAlgorithm} values respectively is optional;
     * neither the portability nor interoperability can be guaranteed in such cases.
     * 
     * @param name the header name
     * @param value the header value
     * @return JwtEncryptionBuilder
     */
    JwtEncryptionBuilder header(String name, Object value);
}
