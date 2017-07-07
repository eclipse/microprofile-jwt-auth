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
package org.eclipse.microprofile.jwt.test.format;

import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.PemUtils;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.JsonWebToken;
import org.testng.annotations.Test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;

/**
 * Created by starksm on 7/6/17.
 */
public class TestCreate {

    @Test
    public void testJWT1() throws Exception {
        InputStream pkIS = getClass().getResourceAsStream("/privateKey.pem");
        BufferedReader bis = new BufferedReader(new InputStreamReader(pkIS));
        String privateKeyPem = bis.readLine();
        PrivateKey pk = PemUtils.decodePrivateKey(privateKeyPem);
        InputStream contentIS = getClass().getResourceAsStream("/jwk-content1.json");
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        byte[] content = new byte[length];
        System.arraycopy(tmp, 0, content, 0, length);
        String jwt = new JWSBuilder()
                .type("Bearer")
                .kid("some-key")
                .content(content)
                .rsa256(pk);
        System.out.printf("jwt: %s\n", jwt);

        JWSInput input = new JWSInput(jwt);
        JsonWebToken jwtObj = input.readJsonContent(JsonWebToken.class);
        Map<String, Object> otherClaims = jwtObj.getOtherClaims();
        System.out.printf("otherClaims.keys: %s\n", otherClaims.keySet());
        List roleNames = (List) otherClaims.get("roles");
        System.out.printf("roles: %s\n", roleNames);
        System.out.printf("groups: %s\n", otherClaims.get("groups"));
        System.out.printf("preferred_username: %s\n", otherClaims.get("preferred_username"));
        System.out.printf("unique_username: %s\n", otherClaims.get("unique_username"));
        Map resourceAccess = (Map) otherClaims.get("resource_access");
        System.out.printf("resource_access(%s): keys:%s; %s\n", resourceAccess.getClass(), resourceAccess.keySet(), resourceAccess);
        for(Object key : resourceAccess.keySet()) {
            Object value = resourceAccess.get(key);
            System.out.printf("%s: %s\n", key, value.getClass());
        }

    }

    public static void main(String[] args) {
        KeyPair kp = KeyUtils.generateRsaKeyPair(1024);
        String publilcKeyPem = PemUtils.encodeKey(kp.getPublic());
        String privateKeyPem = PemUtils.encodeKey(kp.getPrivate());
        System.out.printf("publicKey: %s\n", publilcKeyPem);
        System.out.printf("privateKeyPem: %s\n", privateKeyPem);
    }

}
