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
package org.eclipse.microprofile.jwt.config;

/**
 * Constants for the names of the MP-config properties that MP-JWT implementations must support externalization
 * of to ensure portable setup of MP-JWT implementations.
 */
public class Names {
    /**
     * The PEM encoded public key of the MP-JWT signer
     * TODO: decide if this should be dropped. If not, a standard Converter&lt;PublicKey&gt;
     *     should be provided with the appropriate META-INF/services/... definition
     */
    public final static String VERIFIER_PUBLIC_KEY = "org.eclipse.microprofile.authentication.JWT.verifierPublicKey";

    /**
     * The expected iss claim value to validate against an MP-JWT
     */
    public final static String ISSUER = "org.eclipse.microprofile.authentication.JWT.issuer";
    /**
     * The expected iss claim value(s) as an array to validate against an MP-JWT
     * TODO: are both a single and array values needed?
     */
    public final static String ISSUERS = "org.eclipse.microprofile.authentication.JWT.issuers";

    /**
     * The allowed clock skew in seconds to use when validate the MP-JWT exp claim
     */
    public final static String CLOCK_SKEW = "org.eclipse.microprofile.authentication.JWT.clockSkew";

    /**
     * The URI of an endpoint providing a JSON Web Key Set (JWKS) for the allowed signers of the MP-JWT.
     * The type of this property is a String or URI
     * The keys in the returned key set must include the following parameters:
     * "kty": "RSA",
     * "use": "sig",
     * "alg": "RS256",
     * "n" (Modulus) Parameter
     * "e" (Exponent) Parameter
     */
    public final static String VERIFIER_JWKS_URI = "org.eclipse.microprofile.authentication.JWT.VERIFIER_JWKS_URI";

    /**
     * The interval in minutes that the contents of the VERIFIER_JWKS_URI may be cached without reloading.
     */
    public final static String VERIFIER_JWKS_REFRESH_INTERVAL = "org.eclipse.microprofile.authentication.JWT.VERIFIER_JWKS_REFRESH_INTERVAL";

    private Names(){}
}
