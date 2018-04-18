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

import java.net.URL;

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
     *
     * @throws Exception
     */
    @Test
    public void testJwksURL() throws Exception {
        URL signerJwk = new URL("jwks:/signer.jwk");
        String signerJwkContent = signerJwk.getContent().toString();
        System.out.println(signerJwkContent);
        Assert.assertTrue(signerJwkContent.length() > 450, "Expect more than 450 chars in signer.jwk");
    }
    @Test
    public void testPemJwksURL() throws Exception {
        URL signerJwk = new URL("pemjwks:/publicKey.pem?kid=pem-test");
        String signerJwkContent = signerJwk.getContent().toString();
        System.out.println(signerJwkContent);
        Assert.assertTrue(signerJwkContent.length() > 400, "Expect more than 450 chars in publicKey.pem jwks");
    }
}
