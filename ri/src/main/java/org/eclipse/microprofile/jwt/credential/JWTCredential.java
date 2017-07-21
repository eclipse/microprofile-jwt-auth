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
package org.eclipse.microprofile.jwt.credential;

import javax.security.enterprise.credential.Credential;

/**
 * Represents the Authentication: Bearer {token} information for the JWT
 */
public class JWTCredential implements Credential {
    private String token;

    /**
     * Parse out the token porition of a HTTP "Authentication: Bearer {token}"
     * @param authorizationHeader - HTTP Authentication header with Bearer ... value
     * @return a credential containing the token if the authorization header was for a bearer token, null otherwise
     */
    public static JWTCredential parse(String authorizationHeader) {
        JWTCredential credential = null;
        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            credential = new JWTCredential(token);
        }
        return credential;
    }

    /**
     * Constructor
     *
     * @param token HTTP Bearer Authentication header Bearer token value
     */
    public JWTCredential(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

}
