/*
 * Copyright (c) 2016-2020 Contributors to the Eclipse Foundation
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
package org.eclipse.microprofile.jwt.tck.config;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;

/**
 * Scaled down version of tck TokenUtils that has no JWT library dependencies so that it can be embedded in the tck wars
 * without needing a JWT library on the server side.
 */
public class SimpleTokenUtils {
    private SimpleTokenUtils() {
    }

    /**
     * Decode a PEM encoded private key string to an RSA PrivateKey
     *
     * @param pemEncoded
     *            - PEM string for private key
     * @return PrivateKey
     * @throws Exception
     *             on decode failure
     */
    public static PrivateKey decodePrivateKey(final String pemEncoded) throws Exception {
        byte[] encodedBytes = toEncodedBytes(pemEncoded);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

    /**
     * Decode a PEM encoded public key string to an RSA PublicKey
     *
     * @param pemEncoded
     *            - PEM string for public key
     * @return RSAPublicKey
     * @throws Exception
     *             on decode failure
     */
    public static RSAPublicKey decodePublicKey(String pemEncoded) throws Exception {
        byte[] encodedBytes = toEncodedBytes(pemEncoded);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }

    /**
     * Decode a PEM encoded public key string to an EC PublicKey
     *
     * @param pemEncoded
     *            - PEM string for public key
     * @return ECPublicKey
     * @throws Exception
     *             on decode failure
     */
    public static ECPublicKey decodeECPublicKey(String pemEncoded) throws Exception {
        byte[] encodedBytes = toEncodedBytes(pemEncoded);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPublicKey) kf.generatePublic(spec);
    }

    /**
     * Decode a JWK(S) encoded public key string to an RSA PublicKey
     *
     * @param jwksValue
     *            - JWKS string value
     * @return RSAPublicKey from RSAPublicKeySpec
     */
    public static RSAPublicKey decodeJWKSPublicKey(String jwksValue) throws Exception {
        JsonObject jwks = Json.createReader(new StringReader(jwksValue)).readObject();
        JsonArray keys = jwks.getJsonArray("keys");
        JsonObject jwk;
        if (keys != null) {
            jwk = keys.getJsonObject(0);
        } else {
            jwk = jwks;
        }
        String e = jwk.getString("e");
        String n = jwk.getString("n");

        byte[] ebytes = Base64.getUrlDecoder().decode(e);
        BigInteger publicExponent = new BigInteger(1, ebytes);
        byte[] nbytes = Base64.getUrlDecoder().decode(n);
        BigInteger modulus = new BigInteger(1, nbytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        return (RSAPublicKey) kf.generatePublic(rsaPublicKeySpec);
    }

    /**
     * Decode a JWK(S) encoded private key string to an RSA PrivateKey
     *
     * @param jwksValue
     *            - JWKS string value
     * @return PrivateKey from RSAPrivateKeySpec
     */
    public static PrivateKey decodeJWKSPrivateKey(String jwksValue) throws Exception {
        JsonObject jwks = Json.createReader(new StringReader(jwksValue)).readObject();
        JsonArray keys = jwks.getJsonArray("keys");
        JsonObject jwk;
        if (keys != null) {
            jwk = keys.getJsonObject(0);
        } else {
            jwk = jwks;
        }
        String d = jwk.getString("d");
        String n = jwk.getString("n");

        byte[] dbytes = Base64.getUrlDecoder().decode(d);
        BigInteger privateExponent = new BigInteger(1, dbytes);
        byte[] nbytes = Base64.getUrlDecoder().decode(n);
        BigInteger modulus = new BigInteger(1, nbytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        return kf.generatePrivate(rsaPrivateKeySpec);
    }

    private static byte[] toEncodedBytes(final String pemEncoded) {
        final String normalizedPem = removeBeginEnd(pemEncoded);
        return Base64.getDecoder().decode(normalizedPem);
    }
    private static String removeBeginEnd(String pem) {
        pem = pem.replaceAll("-----BEGIN (.*)-----", "");
        pem = pem.replaceAll("-----END (.*)----", "");
        pem = pem.replaceAll("\r\n", "");
        pem = pem.replaceAll("\n", "");
        return pem.trim();
    }
    /**
     * Read a classpath resource into a string and return it.
     *
     * @param resName
     *            - classpath resource name
     * @return the resource content as a string
     * @throws IOException
     *             - on failure
     */
    public static String readResource(String resName) throws IOException {
        // Strip any classpath: prefix
        if (resName.startsWith("classpath:")) {
            resName = resName.substring(10);
        }
        InputStream is = SimpleTokenUtils.class.getResourceAsStream(resName);
        StringWriter sw = new StringWriter();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
            String line = br.readLine();
            while (line != null) {
                sw.write(line);
                sw.write('\n');
                line = br.readLine();
            }
        }
        return sw.toString();
    }
}
