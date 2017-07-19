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
package org.eclipse.microprofile.jwt.test.cdi;

import org.eclipse.microprofile.jwt.identitystore.JWTAuthContextInfo;
import org.keycloak.common.util.PemUtils;

import javax.annotation.PostConstruct;
import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.interfaces.RSAPublicKey;

/**
 * A simple producer for JWTAuthContextInfo needed for verify the test tokens
 */
public class JWTAuthContextInfoProvider {
    private JWTAuthContextInfo contextInfo;

    /**
     * Create the JWTAuthContextInfo using https://server.example.com as the issuer and the test resources
     * publicKey.pem as the public key of the signer.
     *
     * @throws Exception on failure
     */
    @PostConstruct
    void init() {
        contextInfo = new JWTAuthContextInfo();
        contextInfo.setIssuedBy("https://server.example.com");
        InputStream pkIS = getClass().getResourceAsStream("/publicKey.pem");
        BufferedReader bis = new BufferedReader(new InputStreamReader(pkIS));
        try {
            String publicKeyPem = bis.readLine();
            RSAPublicKey pk = (RSAPublicKey) PemUtils.decodePublicKey(publicKeyPem);
            contextInfo.setSignerKey(pk);
        }
        catch (IOException e) {
            throw new IllegalStateException("Failed to load public key", e);
        }
    }

    @Produces
    @Dependent
    JWTAuthContextInfo testContextInfo() {
        return contextInfo;
    }
}
