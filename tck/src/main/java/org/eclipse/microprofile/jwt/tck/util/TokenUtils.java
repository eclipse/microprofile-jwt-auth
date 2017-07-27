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
package org.eclipse.microprofile.jwt.tck.util;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.keycloak.common.util.PemUtils;
import org.keycloak.jose.jws.JWSBuilder;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.Set;

/**
 * Utiltities for generating a JWT for testing
 */
public class TokenUtils {
    private TokenUtils(){}

    /**
     * Enums to indicate which claims should be set to invalid values for testing failure modes
     */
    public enum InvalidFields {
        ISSUER, // Set an invalid issuer
        EXP,    // Set an invalid expiration
        SIGNER  // Sign the token with the incorrect private key
    }
    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the privateKey.pem
     * test resource key.
     *
     * @param jsonResName - name of test resources file
     * @return the JWT string
     * @throws Exception on parse failure
     */
    public static String generateTokenString(String jsonResName) throws Exception {
        return generateTokenString(jsonResName, Collections.emptySet());
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the privateKey.pem
     * test resource key.
     *
     * @param jsonResName - name of test resources file
     * @param invalidFields - the set of claims that should be added with invalid values to test failure modes
     * @return the JWT string
     * @throws Exception on parse failure
     */
    public static String generateTokenString(String jsonResName, Set<InvalidFields> invalidFields) throws Exception {
        if(invalidFields == null) {
            invalidFields = Collections.emptySet();
        }
        InputStream contentIS = TokenUtils.class.getResourceAsStream(jsonResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        byte[] content = new byte[length];
        System.arraycopy(tmp, 0, content, 0, length);

        JsonParser parser = new JsonParser();
        JsonElement jsonElement = parser.parse(new StringReader(new String(content)));
        JsonObject jwtContent = jsonElement.getAsJsonObject();
        // Change the issuer to INVALID_ISSUER for failure testing if requested
        if(invalidFields.contains(InvalidFields.ISSUER)) {
            jwtContent.addProperty("iss", "INVALID_ISSUER");
        }
        jwtContent.addProperty("iat", currentTimeInSecs());
        jwtContent.addProperty("auth_time", currentTimeInSecs());
        // If the exp claim is not updated, it will be an old value that should be seen as expired
        if(!invalidFields.contains(InvalidFields.EXP)) {
            jwtContent.addProperty("exp", currentTimeInSecs() + 300);
        }
        System.out.println(jwtContent);

        PrivateKey pk;
        if(invalidFields.contains(InvalidFields.SIGNER)) {
            // Generate a new random private key to sign with to test invalid signatures
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair keyPair = generator.generateKeyPair();
            pk = keyPair.getPrivate();
        }
        else {
            // Use the test private key associated with the test public key for a valid signature
            InputStream pkIS = TokenUtils.class.getResourceAsStream("/privateKey.pem");
            BufferedReader bis = new BufferedReader(new InputStreamReader(pkIS));
            String privateKeyPem = bis.readLine();
            pk = PemUtils.decodePrivateKey(privateKeyPem);
        }

        String jwt = new JWSBuilder()
                .type("Bearer")
                .kid("privateKey.pem")
                .content(jwtContent.toString().getBytes())
                .rsa256(pk);
        return jwt;
    }

    /**
     * @return the current time in seconds since epoch
     */
    private static int currentTimeInSecs() {
        long currentTimeMS = System.currentTimeMillis();
        int currentTimeSec = (int) (currentTimeMS / 1000);
        return currentTimeSec;
    }

    public static void main(String[] args) throws Exception {
        generateTokenString("/RolesEndpoint.json");
    }

}
