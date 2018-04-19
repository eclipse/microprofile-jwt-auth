/*
 * Copyright (c) 2016-2018 Contributors to the Eclipse Foundation
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
package jwks;

import java.io.StringReader;
import java.net.URL;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Tests of the jwks and pemjwks URL protocol handlers
 */
public class JWKSResTest {
    /**
     * Install the custom protocol handlers using the java.protocol.handler.pkgs system property
     */
    @BeforeClass
    public static void installURLHandler() {
        // If other handlers are registered, don't overwrite them...
        String oldPkgs = System.getProperty("java.protocol.handler.pkgs", "");
        String newPkgs = "url";
        if(!oldPkgs.isEmpty()) {
            newPkgs += "|" + oldPkgs;
        }
        // Update handler packages
        System.out.printf("Updating java.protocol.handler.pkgs to: %s\n", newPkgs);
        System.setProperty("java.protocol.handler.pkgs", newPkgs);
    }

    /**
     * Validate that the jwks: protocol handler works
     * @throws Exception on failure
     */
    @Test
    public void testJwksURL() throws Exception {
        // Load the /signer-keyset.jwk resource from the classpath as a JWKS
        URL signerJwk = new URL("jwks:/signer-keyset.jwk");
        String signerJwksContent = signerJwk.getContent().toString();
        System.out.println(signerJwksContent);
        JsonObject jwks = Json.createReader(new StringReader(signerJwksContent)).readObject();
        JsonArray keys = jwks.getJsonArray("keys");
        JsonObject key = keys.getJsonObject(0);
        Assert.assertEquals(key.getJsonString("kty").getString(), "RSA");
        Assert.assertEquals(key.getJsonString("use").getString(), "sig");
        Assert.assertEquals(key.getJsonString("kid").getString(), "jwk-test");
        Assert.assertEquals(key.getJsonString("alg").getString(), "RS256");
        Assert.assertEquals(key.getJsonString("e").getString(), "AQAB");
        Assert.assertTrue(key.getJsonString("n").getString().startsWith("uGU_nmjYC7cKRR89NCAo"));
    }
    /**
     * Validate that the pemjwks: protocol handler works
     * @throws Exception on failure
     */
    @Test
    public void testPemJwksURL() throws Exception {
        // Load the /publicKey.pem resource from the classpath as a JWKS
        URL signerJwk = new URL("pemjwks:/publicKey.pem?kid=pem-test");
        String signerJwksContent = signerJwk.getContent().toString();
        System.out.println(signerJwksContent);
        JsonObject jwks = Json.createReader(new StringReader(signerJwksContent)).readObject();
        JsonArray keys = jwks.getJsonArray("keys");
        JsonObject key = keys.getJsonObject(0);
        Assert.assertEquals(key.getJsonString("kty").getString(), "RSA");
        Assert.assertEquals(key.getJsonString("use").getString(), "sig");
        Assert.assertEquals(key.getJsonString("kid").getString(), "pem-test");
        Assert.assertEquals(key.getJsonString("alg").getString(), "RS256");
        Assert.assertEquals(key.getJsonString("e").getString(), "AQAB");
        Assert.assertTrue(key.getJsonString("n").getString().startsWith("livFI8qB4D0y2jy0Cf"));
    }
}
