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
package org.eclipse.microprofile.jwt;

import java.io.Serializable;
import java.security.Principal;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * A read-only interface for the the claims required by Eclipse MicroProfile conforming tokens. Additional information
 * about the claims defined by OIDC and RFC7519 can be found at https://www.iana.org/assignments/jwt/jwt.xhtml.
 *
 * This is compatible with the pre-JSR 375 caller {@link Principal} api.
 */
public interface JWTPrincipal extends Principal {

    /** {@link #getIssuer()} */
    String ISSUER="iss";

    /** {@link #getGroups()} */
    String GROUPS="groups";

    /** {@link #getAudience()} */
    String AUDIENCE="aud";

    /** {@link #getExpirationTime()} ()} */
    String  EXPIRY ="exp";

    /** {@link #getIssuedAtTime()} */
    String ISSURE_TIME="iat";

    /** {@link #getSubject()} */
    String SUBJECT="sub";

    /** {@link #getName()}  */
    String PRINCIPAL_NAME="upn";

    /** {@link #getTokenID()} */
    String TOKEN_ID = "jti";

    /**
     * Returns the unique name of this principal. This either comes from the upn claim, or if that is missing, the
     * preferred_username claim. Note that for guaranteed interoperability a upn claim should be used.
     *
     * @return the unique name of this principal.
     */
    @Override
    String getName();

    /**
     * Get the raw bearer token string originally passed in the authentication header
     * @return raw bear token string
     */
    String getRawToken();

    /**
     * The iss(Issuer) claim identifies the principal that issued the JWT
     * @return the iss claim.
     */
    default String getIssuer() {
        return getClaim(ISSUER);
    }

    /**
     * The aud(Audience) claim identifies the recipients that the JWT is intended for.
     * @return the aud claim.
     */
    default Stream<String> getAudience() {
        return getClaim(AUDIENCE);
    }

    /**
     * The sub(Subject) claim identifies the principal that is the subject of the JWT. This is the token issuing
     * IDP subject, not the
     *
     * @return the sub claim.
     */
    default String getSubject() {
        return getClaim(SUBJECT);
    }

    /**
     * The jti(JWT ID) claim provides a unique identifier for the JWT.
     The identifier value MUST be assigned in a manner that ensures that
     there is a negligible probability that the same value will be
     accidentally assigned to a different data object; if the application
     uses multiple issuers, collisions MUST be prevented among values
     produced by different issuers as well.  The "jti" claim can be used
     to prevent the JWT from being replayed.
     * @return the jti claim.
     */
    default String getTokenID() {
        return getClaim(TOKEN_ID);
    }

    /**
     * The exp (Expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted
     * for processing in seconds since 1970-01-01T00:00:00Z UTC
     * @return the exp claim.
     */
    default Long getExpirationTime() {
        return getClaim(EXPIRY);
    }

    /**
     * The iat(Issued at time) claim identifies the time at which the JWT was issued in seconds since 1970-01-01T00:00:00Z UTC
     * @return the iat claim
     */
    default Long getIssuedAtTime() {
        return getClaim(ISSURE_TIME);
    }

    /**
     * The groups claim provides the group names the JWT principal has been granted.
     *
     * This is a MicroProfile specific claim.
     * @return a possibly empty set of group names.
     */
    default Stream<String> getGroups() {
        return getClaim(GROUPS);
    }

    /**
     * Access the names of all claims are associated with this token.
     * @return non-standard claim names in the token
     */
    Stream<String> getClaimNames();

    boolean containsClaim(String claimName);

    /**
     * Access the value of the indicated claim.
     * @param claimName - the name of the claim
     * @return the value of the indicated claim if it exists, null otherwise.
     */
    <T extends Serializable> T getClaim(String claimName);

    default <T extends Serializable> Optional<T> claim(String claimName) {
        return Optional.ofNullable(getClaim(claimName));
    }
}
