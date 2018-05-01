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
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.testng.annotations.Test;

/**
 * Tests of interchanging JWKs to PEM
 */
public class JWKxPEMTest {
    @Test
    public void outputPEMfromJWKs() throws Exception {
        String json = TokenUtils.readResource("/signer-keyset4k.jwk");
        System.out.printf("jwk: %s\n", json);
        JsonWebKeySet jwks = new JsonWebKeySet(json);
        RsaJsonWebKey rsaJsonWebKey = (RsaJsonWebKey) jwks.findJsonWebKey("jwks4k-test", "RSA", "sig", "RS256");
        RSAPublicKey pk = rsaJsonWebKey.getRsaPublicKey();
        String pem = new String(Base64.getEncoder().encode(pk.getEncoded()));
        System.out.printf("pem: %s\n", pem);
        // Use the formatted output
        System.out.println("-----BEGIN PUBLIC KEY-----");
        int begin = 0;
        String line = pem.substring(begin, 64);
        System.out.println(line);
        begin += 64;
        while(begin < pem.length()) {
            int end = Math.min(begin+64, pem.length());
            line = pem.substring(begin, end);
            System.out.println(line);
            begin += 64;
        }
        System.out.println("-----END PUBLIC KEY-----");
    }

    @Test
    public void outputJWKsfromPEM() throws Exception {
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey4k.pem");
        JsonObjectBuilder jwksBuilder = Json.createObjectBuilder();
        JsonObjectBuilder keyBuilder = Json.createObjectBuilder();
        BigInteger nBI = publicKey.getModulus();
        byte[] nbytes = nBI.toByteArray();
        if ((nBI.bitLength() % 8 == 0) && nbytes[0] == 0 && nbytes.length > 1) {
            byte[] tmp = new byte[nbytes.length-1];
            System.arraycopy(nbytes, 1, tmp, 0, tmp.length);
            nbytes = tmp;
        }
        String n = new String(Base64.getUrlEncoder().withoutPadding().encode(nbytes));
        BigInteger eBI = publicKey.getPublicExponent();
        byte[] ebytes = eBI.toByteArray();
        if ((eBI.bitLength() % 8 == 0) && ebytes[0] == 0 && ebytes.length > 1) {
            byte[] tmp = new byte[nbytes.length-1];
            System.arraycopy(nbytes, 1, tmp, 0, tmp.length);
            ebytes = tmp;
        }
        String e = new String(Base64.getUrlEncoder().withoutPadding().encode(ebytes));

        keyBuilder
            .add("kty", "RSA")
            .add("use", "sig")
            .add("alg", "RS256")
            .add("kid", "pem-to-jwks")
            .add("e", e)
            .add("n", n);
        JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
        arrayBuilder.add(keyBuilder);
        jwksBuilder.add("keys", arrayBuilder);
        JsonObject jwks = jwksBuilder.build();
        String json = jwks.toString();
        System.out.printf("jwks=%s\n", json);
    }

    @Test
    public void generatePublicKeyFromJWKs() throws Exception {
        String jsonJwk = TokenUtils.readResource("/signer-keyset4k.jwk");
        System.out.printf("jwk: %s\n", jsonJwk);
        JsonObject jwks = Json.createReader(new StringReader(jsonJwk)).readObject();
        JsonArray keys = jwks.getJsonArray("keys");
        JsonObject jwk = keys.getJsonObject(0);
        String e = jwk.getString("e");
        String n = jwk.getString("n");

        byte[] ebytes = Base64.getUrlDecoder().decode(e);
        BigInteger publicExponent = new BigInteger(1, ebytes);
        byte[] nbytes = Base64.getUrlDecoder().decode(n);
        BigInteger modulus = new BigInteger(1, nbytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        PublicKey publicKey = kf.generatePublic(rsaPublicKeySpec);
        System.out.printf("publicKey=%s\n", publicKey);
        String pem = new String(Base64.getEncoder().encode(publicKey.getEncoded()));
        System.out.printf("pem: %s\n", pem);
    }
}
