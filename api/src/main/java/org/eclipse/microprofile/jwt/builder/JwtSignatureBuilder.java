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

import java.security.PrivateKey;

import javax.crypto.SecretKey;

import org.eclipse.microprofile.jwt.algorithm.SignatureAlgorithm;

/**
 * JWT JsonWebSignature Builder.
 * 
 * <p>
 * JwtSignatureBuilder implementations must set the 'alg' (algorithm) header to 'RS256'
 * and 'typ' (token type) header to 'JWT' unless they have already been set.
 * <p>
 * Note that JwtSignatureBuilder implementations are not expected to be thread-safe.
 * 
 * @see <a href="https://tools.ietf.org/html/rfc7515">RFC7515</a>
 */
public interface JwtSignatureBuilder extends JwtSignature {

    /**
     * Set a signature algorithm.
     * Note that only the 'RS256' algorithm must be supported.
     * 
     * @param algorithm the signature algorithm
     * @return JwtSignatureBuilder
     */
    JwtSignatureBuilder signatureAlgorithm(SignatureAlgorithm algorithm);

    /**
     * Set a 'kid' signature key id
     * 
     * @param keyId the key id
     * @return JwtSignatureBuilder
     */
    JwtSignatureBuilder signatureKeyId(String keyId);

    /**
     * Custom JWT signature header.
     * 
     * Supporting the 'alg' (algorithm) not matching one the {@link SignatureAlgorithm} values
     * is optional; neither the portability nor interoperability can be guaranteed in such cases.
     * 
     * @param name the header name
     * @param value the header value
     * @return JwtSignatureBuilder
     */
    JwtSignatureBuilder header(String name, Object value);

    /**
     * Sign the claims with {@link PrivateKey} and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     *
     * @param signingKey the signing key
     * @return JwtEncryptionBuilder
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryptionBuilder innerSign(PrivateKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with {@link SecretKey} and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     * 
     * @param signingKey the signing key
     * @return JwtEncryptionBuilder
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryptionBuilder innerSign(SecretKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with a key loaded from the location set with the "mp.jwt.sign.key-location" property
     * and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     * 
     * If no "smallrye.jwt.sign.key-location" property is set then an insecure inner JWT with a "none" algorithm
     * has to be created before being encrypted.
     * 
     * @return JwtEncryptionBuilder
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryptionBuilder innerSign() throws JwtSignatureException;

}
