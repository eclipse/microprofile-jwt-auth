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

/**
 * JWT JsonWebSignature.
 */
public interface JwtSignature {

    /**
     * Sign the claims with {@link PrivateKey}.
     * 'RS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     * 
     * @param signingKey the signing key
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String sign(PrivateKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with {@link SecretKey}.
     * 
     * Supporting the secret keys is optional and the interoperability can not be guaranteed in such cases.
     *
     * @param signingKey the signing key
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String sign(SecretKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with a private or secret key loaded from the file system or HTTPS URI location
     * which can point to a PEM, JWK or JWK set keys.
     * 'RS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     * 
     * @param keyLocation the signing key location
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String sign(String keyLocation) throws JwtSignatureException;

    /**
     * Sign the claims with a key loaded from the file system or HTTPS URI location set with
     * the "mp.jwt.sign.key-location" property which can point to a PEM, JWK or JWK set keys.
     * 'RS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     *
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String sign() throws JwtSignatureException;

    /**
     * Sign the claims with {@link PrivateKey} and encrypt the inner JWT by moving to {@link JwtEncryption}.
     * 'RS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     *
     * @param signingKey the signing key
     * @return JwtEncryption
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryption innerSign(PrivateKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with {@link SecretKey} and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     * 
     * Supporting the secret keys is optional and the interoperability can not be guaranteed in such cases.
     *
     * @param signingKey the signing key
     * @return JwtEncryption
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryption innerSign(SecretKey signingKey) throws JwtSignatureException;

    /**
     * Sign the claims with a private or secret key loaded from the file system or HTTPS URI location
     * which can point to a PEM, JWK or JWK set keys and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     * 'RS256' algorithm will be used unless a different one has been set with {@code JwtSignatureBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     *
     * @param keyLocation the signing key location
     * @return JwtEncryption
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryption innerSign(String keyLocation) throws JwtSignatureException;

    /**
     * Sign the claims with a key loaded from the file system or HTTPS URI location set with the
     * "mp.jwt.sign.key-location" property and encrypt the inner JWT by moving to {@link JwtEncryptionBuilder}.
     *
     * If no "mp.jwt.sign.key-location" property and 'alg' algorithm header have been set then an insecure
     * inner JWT with a "none" algorithm has to be created before being encrypted.
     * A key of size 2048 bits or larger MUST be used with the 'RS256' algorithm.
     * 
     * @return JwtEncryption
     * @throws JwtSignatureException the exception if the inner JWT signing operation has failed
     */
    JwtEncryption innerSign() throws JwtSignatureException;

}
