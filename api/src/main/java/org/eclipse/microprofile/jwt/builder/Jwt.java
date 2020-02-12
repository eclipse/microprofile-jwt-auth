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

import java.util.Map;

import org.eclipse.microprofile.jwt.builder.spi.JwtProvider;

/**
 * Factory class for creating {@link JwtClaimsBuilder} which produces
 * signed, encrypted or signed first and then encrypted JWT tokens.
 *
 * <p>
 * The following example shows how to initialize a {@link JwtClaimsBuilder} from an existing resource
 * containing the claims in a JSON format and produce a signed JWT token with a configured signing key:
 * 
 * <pre>
 * <code>
 * String = Jwt.claims("/tokenClaims.json").sign();
 * </code>
 * </pre>
 * <p>
 * The next example shows how to use {@link JwtClaimsBuilder} to add the claims and encrypt a JSON
 * representation of these claims with a configured encrypting key:
 * 
 * <pre>
 * <code>
 * String = Jwt.claims().issuer("https://issuer.org").claim("custom-claim", "custom-value").encrypt();
 * </code>
 * </pre>
 * <p>
 * The final example shows how to initialize a {@link JwtClaimsBuilder} from an existing resource
 * containing the claims in a JSON format, produce an inner signed JWT token with a configured signing key
 * and encrypt it with a configured encrypting key.
 * 
 * <pre>
 * <code>
 * String = Jwt.claims("/tokenClaims.json").innerSign().encrypt();
 * </code>
 * </pre>
 */
public final class Jwt {
    private Jwt() {
        
    }
    /**
     * Creates a new instance of {@link JwtClaimsBuilder}
     *
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder claims() {
        return JwtProvider.provider().claims();
    }

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} from a map of claims.
     * 
     * @param claims the map with the claim name and value pairs. Claim value is converted to String unless it is
     *        an instance of {@code Boolean}, {@code Number}, {@code Collection}, {@code Map},
     *        {@code JsonObject} or {@code JsonArray}.
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder claims(Map<String, Object> claims) {
        return JwtProvider.provider().claims(claims);
    }

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} from a JSON resource.
     * 
     * @param jsonLocation JSON resource location which can point to the local filesystem, classpath or external URI.
     * @return {@link JwtClaimsBuilder}
     */
    public static JwtClaimsBuilder claims(String jsonLocation) {
        return JwtProvider.provider().claims(jsonLocation);
    }
}
