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

import java.security.PublicKey;

import javax.crypto.SecretKey;

/**
 * JWT JsonWebEncryption.
 */
public interface JwtEncryption {

    /**
     * Encrypt the claims or inner JWT with {@link PublicKey}.
     * 'RSA-OAEP' key management and 'A256GCM' content encryption algorithms will be used
     * unless different ones have been set with {@code JwtEncryptionBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RSA-OAEP' algorithm.
     *
     * @param keyEncryptionKey the key which encrypts the content encryption key
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encrypt(PublicKey keyEncryptionKey) throws JwtEncryptionException;

    /**
     * Encrypt the claims or inner JWT with {@link SecretKey}.
     * 
     * Supporting the secret keys is optional and the interoperability can not be guaranteed in such cases. 
     *
     * @param keyEncryptionKey the key which encrypts the content encryption key
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encrypt(SecretKey keyEncryptionKey) throws JwtEncryptionException;

    /**
     * Encrypt the claims or inner JWT with a public or secret key loaded from the
     * file system, classpath or HTTP(S) URI location which can point to a PEM, JWK or JWK set keys.
     * 'RSA-OAEP' key management and 'A256GCM' content encryption algorithms will be used
     * unless different ones have been set with {@code JwtEncryptionBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RSA-OAEP' algorithm.
     *
     * @param keyLocation the location of the keyEncryptionKey which encrypts the content encryption key
     * @return encrypted JWT token
     * @throws JwtEncryptionException the exception if the encryption operation has failed
     */
    String encrypt(String keyLocation) throws JwtEncryptionException;

    /**
     * Encrypt the claims or inner JWT with a key loaded from the file system, classpath or HTTP(S) URI
     * location set with the "mp.jwt.encrypt.key-location" property.
     * 'RSA-OAEP' key management and 'A256GCM' content encryption algorithms will be used
     * unless different ones have been set with {@code JwtEncryptionBuilder}.
     * A key of size 2048 bits or larger MUST be used with the 'RSA-OAEP' algorithm.
     *
     * @return signed JWT token
     * @throws JwtSignatureException the exception if the signing operation has failed
     */
    String encrypt() throws JwtSignatureException;

}
