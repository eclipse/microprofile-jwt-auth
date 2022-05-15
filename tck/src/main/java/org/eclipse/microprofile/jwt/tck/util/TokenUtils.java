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
package org.eclipse.microprofile.jwt.tck.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.eclipse.microprofile.jwt.Claims;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * Utilities for generating a JWT for testing
 */
public class TokenUtils {

    private TokenUtils() {
        // no-op: utility class
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the privateKey.pem test
     * resource key using RS256 algorithm.
     *
     * @param jsonResName
     *            - name of test resources file
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    @Deprecated
    public static String generateTokenString(final String jsonResName) throws Exception {
        return signClaims(jsonResName);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the privateKey.pem test
     * resource key using RS256 algorithm.
     *
     * @param jsonResName
     *            - name of test resources file
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String signClaims(final String jsonResName) throws Exception {
        return signClaims(jsonResName, SignatureAlgorithm.RS256);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the privateKey.pem test
     * resource key using either RS256 or ES256 algorithm.
     *
     * @param jsonResName
     *            - name of test resources file
     * @param algorithm
     *            - signature algorithm
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String signClaims(final String jsonResName, SignatureAlgorithm algorithm) throws Exception {
        return signClaims(jsonResName, algorithm, Collections.emptySet());
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the privateKey.pem test
     * resource key using RS256 algorithm, possibly with invalid fields.
     *
     * @param jsonResName
     *            - name of test resources file
     * @param invalidClaims
     *            - the set of claims that should be added with invalid values to test failure modes
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    @Deprecated
    public static String generateTokenString(final String jsonResName, final Set<InvalidClaims> invalidClaims)
            throws Exception {
        return signClaims(jsonResName, SignatureAlgorithm.RS256, invalidClaims);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the privateKey.pem test
     * resource key using either RS256 or ES256 algorithm, possibly with invalid fields.
     *
     * @param jsonResName
     *            - name of test resources file
     * @param algorithm
     *            - signature algorithm
     * @param invalidClaims
     *            - the set of claims that should be added with invalid values to test failure modes
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String signClaims(final String jsonResName, SignatureAlgorithm algorithm,
            final Set<InvalidClaims> invalidClaims) throws Exception {
        return signClaims(jsonResName, algorithm, invalidClaims, null);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the privateKey.pem test
     * resource key using RS256 algorithm, possibly with invalid fields and custom time fields.
     *
     * @param jsonResName
     *            - name of test resources file
     * @param invalidClaims
     *            - the set of claims that should be added with invalid values to test failure modes
     * @param timeClaims
     *            - used to return the exp, iat, auth_time claims
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    @Deprecated
    public static String generateTokenString(String jsonResName, Set<InvalidClaims> invalidClaims,
            Map<String, Long> timeClaims) throws Exception {
        return signClaims(jsonResName, SignatureAlgorithm.RS256, invalidClaims, timeClaims);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by either the privateKey.pem
     * test resource using RS256 algorithm or the ecPrivateKey.pem test resource using ES256 algorithm, possibly with
     * invalid fields and custom time claims.
     *
     * @param jsonResName
     *            - name of test resources file
     * @param algorithm
     *            - signature algorithm
     * @param invalidClaims
     *            - the set of claims that should be added with invalid values to test failure modes
     * @param timeClaims
     *            - used to return the exp, iat, auth_time claims
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String signClaims(String jsonResName, SignatureAlgorithm algorithm,
            Set<InvalidClaims> invalidClaims, Map<String, Long> timeClaims) throws Exception {
        // Use the test private key associated with the test public key for a valid signature
        PrivateKey pk = null;
        if (algorithm == SignatureAlgorithm.RS256) {
            pk = readPrivateKey("/privateKey.pem");
        } else {
            pk = readECPrivateKey("/ecPrivateKey.pem");
        }
        return signClaims(pk, jsonResName, jsonResName, invalidClaims, timeClaims);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the private key test resource
     * key using either RS256 or ES256 algorithm, possibly with invalid fields.
     *
     * @param pk
     *            - the private key to sign the token with
     * @param kid
     *            - the kid header to assign to the token
     * @param jsonResName
     *            - name of test resources file
     * @param invalidClaims
     *            - the set of claims that should be added with invalid values to test failure modes
     * @param timeClaims
     *            - used to return the exp, iat, auth_time claims
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    @Deprecated
    public static String generateTokenString(PrivateKey pk, String kid, String jsonResName,
            Set<InvalidClaims> invalidClaims,
            Map<String, Long> timeClaims) throws Exception {
        return signClaims(pk, kid, jsonResName, invalidClaims, timeClaims);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the private key using either
     * RS256 or ES256 algorithm.
     *
     * @param pk
     *            - the private key to sign the token with
     * @param kid
     *            - the kid claim to assign to the token
     * @param jsonResName
     *            - name of test resources file
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String signClaims(PrivateKey pk, String kid, String jsonResName) throws Exception {
        return signClaims(pk, kid, jsonResName, null, null);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the private key using either
     * RS256 or ES256 algorithm, possibly with invalid fields.
     *
     * @param pk
     *            - the private key to sign the token with
     * @param kid
     *            - the kid claim to assign to the token
     * @param jsonResName
     *            - name of test resources file
     * @param invalidClaims
     *            - the set of claims that should be added with invalid values to test failure modes
     * @param timeClaims
     *            - used to return the exp, iat, auth_time claims
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String signClaims(PrivateKey pk, String kid, String jsonResName,
            Set<InvalidClaims> invalidClaims, Map<String, Long> timeClaims) throws Exception {

        if (invalidClaims == null) {
            invalidClaims = Collections.emptySet();
        }
        JwtClaims claims = createJwtClaims(jsonResName, invalidClaims, timeClaims);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        if (kid != null) {
            jws.setKeyIdHeaderValue(kid);
        }
        jws.setHeader("typ", "JWT");

        if (invalidClaims.contains(InvalidClaims.ALG)) {
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
            jws.setKey(KeyGenerator.getInstance("HMACSHA256").generateKey());
        } else {
            jws.setAlgorithmHeaderValue(pk instanceof RSAPrivateKey
                    ? AlgorithmIdentifiers.RSA_USING_SHA256
                    : AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
            if (invalidClaims.contains(InvalidClaims.SIGNER)) {
                // Generate a new random private key to sign with to test invalid signatures
                pk = generateKeyPair(2048).getPrivate();
            }
            jws.setKey(pk);
        }
        jws.setDoKeyValidation(false);
        return jws.getCompactSerialization();
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is encrypted by the publicKey.pem test
     * resource key.
     *
     * @param jsonResName
     *            - name of test resources file
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String encryptClaims(final String jsonResName) throws Exception {
        return encryptClaims(jsonResName, Collections.emptySet());
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is encrypted by the publicKey.pem test
     * resource key, possibly with invalid fields.
     *
     * @param jsonResName
     *            - name of test resources file
     * @param invalidClaims
     *            - the set of claims that should be added with invalid values to test failure modes
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String encryptClaims(final String jsonResName, final Set<InvalidClaims> invalidClaims)
            throws Exception {
        return encryptClaims(jsonResName, invalidClaims, null);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is encrypted by the publicKey.pem test
     * resource key, possibly with invalid fields.
     *
     * @param jsonResName
     *            - name of test resources file
     * @param invalidClaims
     *            - the set of claims that should be added with invalid values to test failure modes
     * @param timeClaims
     *            - used to return the exp, iat, auth_time claims
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String encryptClaims(String jsonResName, Set<InvalidClaims> invalidClaims,
            Map<String, Long> timeClaims) throws Exception {
        // Use the test public key associated with the test private key for a valid JWE encryption
        PublicKey pk = readPublicKey("/publicKey.pem");
        return encryptClaims(pk, jsonResName, jsonResName, invalidClaims, timeClaims);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is encrypted by the public key.
     *
     * @param pk
     *            - the public key to encrypt the token with
     * @param jsonResName
     *            - name of test resources file
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String encryptClaims(PublicKey pk, String jsonResName) throws Exception {
        return encryptClaims(pk, jsonResName, jsonResName);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is encrypted by the public key.
     *
     * @param pk
     *            - the public key to encrypt the token with
     * @param kid
     *            - the kid header to assign to the token
     * @param jsonResName
     *            - name of test resources file
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String encryptClaims(PublicKey pk, String kid, String jsonResName) throws Exception {
        return encryptClaims(pk, kid, jsonResName, null, null);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is encrypted by the public key, possibly
     * with invalid fields.
     *
     * @param pk
     *            - the public key to encrypt the token with
     * @param kid
     *            - the kid header to assign to the token
     * @param jsonResName
     *            - name of test resources file
     * @param invalidClaims
     *            - the set of claims that should be added with invalid values to test failure modes
     * @param timeClaims
     *            - used to return the exp, iat, auth_time claims
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String encryptClaims(PublicKey pk, String kid, String jsonResName, Set<InvalidClaims> invalidClaims,
            Map<String, Long> timeClaims) throws Exception {
        return encryptClaims(pk, null, kid, jsonResName, invalidClaims, timeClaims);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is encrypted by the public key, possibly
     * with invalid fields.
     *
     * @param pk
     *            - the public key to encrypt the token with
     * @param keyAlgorithm
     *            - the key encryption algorithm
     * @param kid
     *            - the kid header to assign to the token
     * @param jsonResName
     *            - name of test resources file
     * @param invalidClaims
     *            - the set of claims that should be added with invalid values to test failure modes
     * @param timeClaims
     *            - used to return the exp, iat, auth_time claims
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String encryptClaims(PublicKey pk, KeyManagementAlgorithm keyAlgorithm, String kid,
            String jsonResName, Set<InvalidClaims> invalidClaims,
            Map<String, Long> timeClaims) throws Exception {
        if (invalidClaims == null) {
            invalidClaims = Collections.emptySet();
        }
        JwtClaims claims = createJwtClaims(jsonResName, invalidClaims, timeClaims);

        Key key = null;
        if (invalidClaims.contains(InvalidClaims.ENCRYPTOR)) {
            // Generate a new random private key to sign with to test invalid signatures
            KeyPair keyPair = generateKeyPair(2048);
            key = keyPair.getPublic();
        } else if (invalidClaims.contains(InvalidClaims.ALG)) {
            key = KeyGenerator.getInstance("AES").generateKey();
        } else {
            key = pk;
        }

        return encryptString(key, keyAlgorithm, kid, claims.toJson(), false);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file by signing it first with the privateKey.pem
     * test resource using RS256 algorithm and encrypting next with the publicKey.pem test resource.
     *
     * @param jsonResName
     *            - name of test resources file
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String signEncryptClaims(String jsonResName) throws Exception {
        return signEncryptClaims(jsonResName, SignatureAlgorithm.RS256);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file by signing it first by either the
     * privateKey.pem test resource using RS256 algorithm or the ecPrivateKey.pem test resource using ES256 algorithm
     * and encrypting it next with the publicKey.pem test resource.
     *
     * @param jsonResName
     *            - name of test resources file
     * @param signatureAlgorithm
     *            - signature algorithm
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String signEncryptClaims(String jsonResName, SignatureAlgorithm signatureAlgorithm) throws Exception {
        PrivateKey signingKey = null;
        if (signatureAlgorithm == SignatureAlgorithm.RS256) {
            signingKey = readPrivateKey("/privateKey.pem");
        } else {
            signingKey = readECPrivateKey("/ecPrivateKey.pem");
        }
        PublicKey encryptionKey = readPublicKey("/publicKey.pem");
        return signEncryptClaims(signingKey, encryptionKey, jsonResName);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file by signing it first with the private key using
     * RS256 algorithm and encrypting next with the public key.
     *
     * @param signingKey
     *            - the private key to sign the token with
     * @param encryptionKey
     *            - the public key to encrypt the token with
     * @param jsonResName
     *            - name of test resources file
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String signEncryptClaims(PrivateKey signingKey,
            PublicKey encryptionKey,
            String jsonResName) throws Exception {
        return signEncryptClaims(signingKey, jsonResName + "-signed", encryptionKey, jsonResName + "-encrypted",
                jsonResName);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file by signing it first with the private key using
     * RS256 algorithm and and encrypting next with the public key.
     *
     * @param signingKey
     *            - the private key to sign the token with
     * @param signingKid
     *            - the signing key identifier
     * @param encryptionKey
     *            - the public key to encrypt the token with
     * @param encryptionKid
     *            - the encryption key identifier
     * @param jsonResName
     *            - name of test resources file
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String signEncryptClaims(PrivateKey signingKey,
            String signingKid,
            PublicKey encryptionKey,
            String encryptionKid,
            String jsonResName) throws Exception {
        return signEncryptClaims(signingKey, signingKid, encryptionKey, encryptionKid, jsonResName, true);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file by signing it first with the private key using
     * RS256 algorithm and encrypting next with the public key with an option to skip setting a content-type 'cty'
     * parameter.
     *
     * @param signingKey
     *            - the private key to sign the token with
     * @param signingKid
     *            - the signing key identifier
     * @param encryptionKey
     *            - the public key to encrypt the token with
     * @param encryptionKid
     *            - the encryption key identifier
     * @param jsonResName
     *            - name of test resources file
     * @param setContentType
     *            - set a content-type 'cty' parameter if true
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String signEncryptClaims(PrivateKey signingKey,
            String signingKid,
            PublicKey encryptionKey,
            String encryptionKid,
            String jsonResName,
            boolean setContentType) throws Exception {

        return signEncryptClaims(signingKey, signingKid, encryptionKey, null, encryptionKid, jsonResName,
                setContentType);
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file by signing it first with the private key using
     * RS256 algorithm and encrypting next with the public key with an option to skip setting a content-type 'cty'
     * parameter.
     *
     * @param signingKey
     *            - the private key to sign the token with
     * @param signingKid
     *            - the signing key identifier
     * @param encryptionKey
     *            - the public key to encrypt the token with
     * @param keyEncryptionAlgorithm
     *            - the key encryption algorithm
     * @param encryptionKid
     *            - the encryption key identifier
     * @param jsonResName
     *            - name of test resources file
     * @param setContentType
     *            - set a content-type 'cty' parameter if true
     * @return the JWT string
     * @throws Exception
     *             on parse failure
     */
    public static String signEncryptClaims(PrivateKey signingKey,
            String signingKid,
            PublicKey encryptionKey,
            KeyManagementAlgorithm keyAlgorithm,
            String encryptionKid,
            String jsonResName,
            boolean setContentType) throws Exception {

        String nestedJwt = signClaims(signingKey, signingKid, jsonResName, null, null);
        return encryptString(encryptionKey, keyAlgorithm, encryptionKid, nestedJwt, setContentType);
    }

    private static String encryptString(Key key, KeyManagementAlgorithm keyAlgorithm, String kid, String plainText,
            boolean setContentType)
            throws Exception {

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPlaintext(plainText);
        if (kid != null) {
            jwe.setKeyIdHeaderValue(kid);
        }
        if (setContentType && plainText.split("\\.").length == 3) {
            // nested JWT
            jwe.setHeader("cty", "JWT");
        }
        jwe.setEncryptionMethodHeaderParameter("A256GCM");

        if (keyAlgorithm != null) {
            jwe.setAlgorithmHeaderValue(keyAlgorithm.getAlgorithm());
        } else {
            if (key instanceof SecretKey) {
                jwe.setAlgorithmHeaderValue("A128KW");
            } else {
                jwe.setAlgorithmHeaderValue("RSA-OAEP");
            }
        }
        jwe.setKey(key);
        return jwe.getCompactSerialization();
    }

    private static JwtClaims createJwtClaims(String jsonResName, Set<InvalidClaims> invalidClaims,
            Map<String, Long> timeClaims) throws Exception {

        String content = readJsonContent(jsonResName);
        JwtClaims claims = JwtClaims.parse(content);

        // Change the issuer to INVALID_ISSUER for failure testing if requested
        if (invalidClaims.contains(InvalidClaims.ISSUER)) {
            claims.setIssuer("INVALID_ISSUER");
        }
        long currentTimeInSecs = currentTimeInSecs();
        long exp = currentTimeInSecs + 300;
        long iat = currentTimeInSecs;
        long authTime = iat;
        boolean expWasInput = false;
        // Check for an input exp to override the default of now + 300 seconds
        if (timeClaims != null && timeClaims.containsKey(Claims.exp.name())) {
            exp = timeClaims.get(Claims.exp.name());
            expWasInput = true;
        }
        // iat and auth_time should be before any input exp value unless 'iat' is expected to be invalid
        if (expWasInput) {
            iat = exp - 5;
            authTime = iat;
        } else if (invalidClaims.contains(InvalidClaims.IAT)) {
            iat = exp + 5;
            authTime = iat;
        }
        claims.setIssuedAt(NumericDate.fromSeconds(iat));
        claims.setClaim(Claims.auth_time.name(), authTime);
        // If the exp claim is not updated, it will be an old value that should be seen as expired
        if (!invalidClaims.contains(InvalidClaims.EXP)) {
            claims.setExpirationTime(NumericDate.fromSeconds(exp));
        }
        // Return the token time values if requested
        if (timeClaims != null) {
            timeClaims.put(Claims.iat.name(), iat);
            timeClaims.put(Claims.auth_time.name(), authTime);
            timeClaims.put(Claims.exp.name(), exp);
        }
        return claims;
    }

    private static String readJsonContent(String jsonResName) throws IOException {
        InputStream contentIS = TokenUtils.class.getResourceAsStream(jsonResName);
        if (contentIS == null) {
            throw new IllegalStateException("Failed to find resource: " + jsonResName);
        }

        try (Scanner s = new Scanner(contentIS)) {
            s.useDelimiter("\\A");
            return s.hasNext() ? s.next() : "";
        }
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
        InputStream is = TokenUtils.class.getResourceAsStream(resName);
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

    /**
     * Read a PEM encoded RSA private key from the classpath
     * 
     * @param pemResName
     *            - key file resource name
     * @return RSAPrivateKey
     * @throws Exception
     *             on decode failure
     */
    public static RSAPrivateKey readPrivateKey(final String pemResName) throws Exception {
        InputStream contentIS = TokenUtils.class.getResourceAsStream(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        return decodePrivateKey(new String(tmp, 0, length));
    }

    /**
     * Read a PEM encoded EC private key from the classpath
     * 
     * @param pemResName
     *            - key file resource name
     * @return ECPrivateKey
     * @throws Exception
     *             on decode failure
     */
    public static ECPrivateKey readECPrivateKey(final String pemResName) throws Exception {
        InputStream contentIS = TokenUtils.class.getResourceAsStream(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        return decodeECPrivateKey(new String(tmp, 0, length));
    }

    /**
     * Read a PEM encoded RSA public key from the classpath
     * 
     * @param pemResName
     *            - key file resource name
     * @return RSAPublicKey
     * @throws Exception
     *             on decode failure
     */
    public static RSAPublicKey readPublicKey(final String pemResName) throws Exception {
        InputStream contentIS = TokenUtils.class.getResourceAsStream(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        return decodePublicKey(new String(tmp, 0, length));
    }

    /**
     * Read a PEM encoded EC public key from the classpath
     * 
     * @param pemResName
     *            - key file resource name
     * @return ECPublicKey
     * @throws Exception
     *             on decode failure
     */
    public static ECPublicKey readECPublicKey(final String pemResName) throws Exception {
        InputStream contentIS = TokenUtils.class.getResourceAsStream(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        return decodeECPublicKey(new String(tmp, 0, length));
    }

    /**
     * Read a public key in JWK format from the classpath
     * 
     * @param jwkResName
     *            - key file resource name
     * @return PublicKey
     * @throws Exception
     *             on decode failure
     */
    public static PublicKey readJwkPublicKey(final String jwkResName) throws Exception {
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(JsonUtil.parseJson(readJsonContent(jwkResName)));
        return PublicJsonWebKey.class.cast(jwk).getPublicKey();
    }

    /**
     * Read a private key in JWK format from the classpath
     * 
     * @param jwkResName
     *            - key file resource name
     * @return PublicKey
     * @throws Exception
     *             on decode failure
     */
    public static PrivateKey readJwkPrivateKey(final String jwkResName) throws Exception {
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(JsonUtil.parseJson(readJsonContent(jwkResName)));
        return PublicJsonWebKey.class.cast(jwk).getPrivateKey();
    }

    /**
     * Generate a new RSA keypair.
     * 
     * @param keySize
     *            - the size of the key
     * @return KeyPair
     * @throws NoSuchAlgorithmException
     *             on failure to load RSA key generator
     */
    public static KeyPair generateKeyPair(final int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    /**
     * Decode a PEM encoded private key string to an RSA PrivateKey
     * 
     * @param pemEncoded
     *            - PEM string for private key
     * @return RSAPrivateKey
     * @throws Exception
     *             on decode failure
     */
    public static RSAPrivateKey decodePrivateKey(final String pemEncoded) throws Exception {
        byte[] encodedBytes = toEncodedBytes(pemEncoded);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(keySpec);
    }

    /**
     * Decode a PEM encoded private key string to an EC PrivateKey
     * 
     * @param pemEncoded
     *            - PEM string for private key
     * @return ECPrivateKey
     * @throws Exception
     *             on decode failure
     */
    public static ECPrivateKey decodeECPrivateKey(final String pemEncoded) throws Exception {
        byte[] encodedBytes = toEncodedBytes(pemEncoded);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPrivateKey) kf.generatePrivate(keySpec);
    }

    /**
     * Decode a PEM encoded public key string to an RSA PublicKey
     * 
     * @param pemEncoded
     *            - PEM string for private key
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
     *            - PEM string for private key
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
     * @return the current time in seconds since epoch
     */
    public static int currentTimeInSecs() {
        long currentTimeMS = System.currentTimeMillis();
        return (int) (currentTimeMS / 1000);
    }

    /**
     * Enums to indicate which claims should be set to invalid values for testing failure modes
     */
    public enum InvalidClaims {
        ISSUER, // Set an invalid issuer
        IAT, // Set an invalid issuance time
        EXP, // Set an invalid expiration
        SIGNER, // Sign the token with the incorrect private key
        ENCRYPTOR, // Encrypt the token with the incorrect public key
        ALG // Sign the token with the correct private key or encrypt the token with the correct public key, but
            // incorrect algorithm
    }
}
