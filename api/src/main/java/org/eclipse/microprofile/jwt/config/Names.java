/*
 * Copyright (c) 2016-2020 Contributors to the Eclipse Foundation
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
package org.eclipse.microprofile.jwt.config;

/**
 * Constants for the names of the MP-config properties that MP-JWT implementations must support externalization
 * of to ensure portable setup of MP-JWT implementations.
 */
public interface Names {
    /**
     * The embedded key material of the verification public key for the MP-JWT signer in PKCS8 PEM or JWK(S) format.  If not found
     * the {@linkplain #VERIFIER_PUBLIC_KEY_LOCATION} needs to be checked.
     */
    String VERIFIER_PUBLIC_KEY = "mp.jwt.verify.publickey";

    /**
     * The relative path or full URL of the verification public key.  All relative paths will be resolved within the archive using
     * ClassLoader.getResource.  If the value is a URL it will be resolved using `new URL(“”).openStream()`
     */
    String VERIFIER_PUBLIC_KEY_LOCATION = "mp.jwt.verify.publickey.location";

    /**
     * Public Key Signature Algorithm property which can be set to either 'RS256' or 'ES256'.
     */
    String VERIFIER_PUBLIC_KEY_ALGORITHM = "mp.jwt.verify.publickey.algorithm";

    /**
     * The relative path or full URL of the decryption key.  All relative paths will be resolved within the archive using
     * ClassLoader.getResource.  If the value is a URL it will be resolved using `new URL(“”).openStream()`
     */
    String DECRYPTOR_KEY_LOCATION = "mp.jwt.decrypt.key.location";

    /**
     * The expected iss claim value to validate against an MP-JWT.
     */
    String ISSUER = "mp.jwt.verify.issuer";

    /**
     * The HTTP header name expected to contain the JWT token.<p>
     *
     * Supported values are <em>Authorization</em> (default) and <em>Cookie</em>.
     */
    String TOKEN_HEADER = "mp.jwt.token.header";

    /**
     * The Cookie name expected to containe the JWT token (default is <em>Bearer</em>).<p>
     *
     * This configuration will be ignored unless `mp.jwt.token.header` is set to `Cookie`.
     */
    String TOKEN_COOKIE = "mp.jwt.token.cookie";
    
    /**
     * The expected "aud" claim value(s), separated by commas. 
     * If specified, MP-JWT claim must be present and match one of the values.
     */
    String AUDIENCES = "mp.jwt.verify.audiences";
}
