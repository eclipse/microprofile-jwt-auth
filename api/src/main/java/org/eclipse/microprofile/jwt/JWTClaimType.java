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


import javax.json.JsonObject;

/**
 * This enum represents the standardized claims that the MP-JWT specification allows for in terms of interoperability.
 * For every claim in this enum, an MP-JWT implementation must return a value of the indicated type from
 * {@link org.eclipse.microprofile.jwt.JWTPrincipal#getClaim(String)} method. An implementation is free to inclue
 * any additional claims, but users of JWTPrincipal can expect no consistency of type for claims not included in
 * this enum.
 *
 * The set of included claims is defined by IANA, see https://www.iana.org/assignments/jwt/jwt.xhtml
 */
public enum JWTClaimType {
    ISS("iss", "Issuer", String.class),
    SUB("sub", "Subject", String.class),
    AUD("aud", "Audience", String[].class),
    EXP("exp", "Expiration Time", Long.class),
    IAT("iat", "Issued At Time", Long.class),
    JTI("jti", "JWT ID", String.class),
    GROUPS("groups", "MP-JWT specific groups permission grant", String[].class),
    RAW_TOKEN("raw_token", "MP-JWT specific original bearer token", String.class),

    //
    NBF("nbf", "Not Before", Long.class),
    AUTH_TIME("auth_time", "Time when the authentication occurred", Long.class),
    UPDATED_AT("updated_at", "Time the information was last updated", Long.class),
    AZP("azp", "Authorized party - the party to which the ID Token was issued", String.class),
    NONCE("nonce", "Value used to associate a Client session with an ID Token", String.class),
    AT_HASH("at_hash", "Access Token hash value", Long.class),
    C_HASH("c_hash", "Code hash value", Long.class),

    FULL_NAME("name", "Full name", String.class),
    FAMILY_NAME("family_name", "Surname(s) or last name(s)", String.class),
    MIDDLE_NAME("middle_name", "Middle name(s)", String.class),
    NICKNAME("nickname", "Casual name", String.class),
    GIVEN_NAME("given_name", "Given name(s) or first name(s)", String.class),
    PREFERRED_USERNAME("preferred_username", "Shorthand name by which the End-User wishes to be referred to", String.class),
    EMAIL("email", "Preferred e-mail address", String.class),
    EMAIL_VERIFIED("email_verified", "True if the e-mail address has been verified; otherwise false", Boolean.class),

//...
    SUB_JWK("sub_jwk", "Public key used to check the signature of an ID Token", JsonObject.class),
    UNKNOWN("unknown", "A catch all for any unknown claim", Object.class)
    ;

    private String name;
    private String description;
    private Class<?> type;
    private JWTClaimType(String name, String description, Class<?> type) {
        this.name = name;
        this.description = description;
        this.type = type;
    }

    /**
     * Get the claim name as seen in the original JSON content
     * @return claim name
     */
    public java.lang.String getName() {
        return name;
    }

    /**
     * @return A desccription for the claim
     */
    public java.lang.String getDescription() {
        return description;
    }

    /**
     * The required type of the claim
     * @return type of the claim
     */
    public Class<?> getType() {
        return type;
    }
}
