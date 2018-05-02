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
public interface Names {
    /**
     * The embedded key material of the public key for the MP-JWT signer in PKCS8 PEM or JWK(S) format.  If not found
     * the {@linkplain #VERIFIER_PUBLIC_KEY_LOCATION} needs to be checked.
     */
    String VERIFIER_PUBLIC_KEY = "mp.jwt.verify.publickey";

    /**
     * The expected iss claim value to validate against an MP-JWT. If not provided, there will be no
     * validation of the MP-JWT iss claim.
     */
    String ISSUER = "mp.jwt.verify.issuer";

    /**
     * The relative path or full URL of the public key.  All relative paths will be resolved within the archive using
     * ClassLoader.getResource.  If the value is a URL it will be resolved using `new URL(“”).openStream()`
     */
    String VERIFIER_PUBLIC_KEY_LOCATION = "mp.jwt.verify.publickey.location";
}
