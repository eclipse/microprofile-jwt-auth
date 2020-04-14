/*
 * Copyright (c) 2020 Contributors to the Eclipse Foundation
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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.eclipse.microprofile.jwt.tck.TCKConstants;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Tests for TokenUtils encryptSignedClaims methods
 */
public class TokenUtilsSignEncryptTest {

    @Test(groups = TCKConstants.TEST_GROUP_UTILS,
        description = "Illustrate an encryption of the nested JWT")
    public void testEncryptSignedClaims() throws Exception {
        String token = TokenUtils.signEncryptClaims("/Token1.json");
        validateToken(token, true);
    }

    @Test(groups = TCKConstants.TEST_GROUP_UTILS, expectedExceptions = {InvalidJwtException.class},
            description = "Illustrate validation failure if signed token is encrypted and no 'cty' header is set")
    public void testEncryptSignedClaimsWithoutCty() throws Exception {
        PrivateKey signingKey = TokenUtils.readPrivateKey("/privateKey.pem");
        PublicKey encryptionKey = TokenUtils.readPublicKey("/publicKey.pem");
        String token =
            TokenUtils.signEncryptClaims(signingKey, "1", encryptionKey, "2", "/Token1.json", false);
        validateToken(token, true);
    }

    @Test(groups = TCKConstants.TEST_GROUP_UTILS, expectedExceptions = {JoseException.class},
            description = "Illustrate validation failure if signed token is used")
    public void testValidateSignedToken() throws Exception {
        String token = TokenUtils.signClaims("/Token1.json");
        validateToken(token, false);
    }

    @Test(groups = TCKConstants.TEST_GROUP_UTILS, expectedExceptions = {InvalidJwtException.class},
            description = "Illustrate validation failure if encrypted token without nested token is used")
    public void testValidateEncryptedOnlyToken() throws Exception {
        String token = TokenUtils.encryptClaims("/Token1.json");
        validateToken(token, false);
    }

    private void validateToken(String jweCompact, boolean jwtExpected) throws Exception {

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmConstraints(
           new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, "RSA-OAEP"));
        jwe.setCompactSerialization(jweCompact);
        RSAPrivateKey privateKey = (RSAPrivateKey) TokenUtils.readPrivateKey("/privateKey.pem");
        jwe.setKey(privateKey);
        String token = jwe.getPlaintextString();

        if (jwtExpected) {
            if (!"JWT".equals(jwe.getHeader("cty"))) {
                throw new InvalidJwtException("'cty' header is missing", Collections.emptyList(), null);
            }
        }
        else {
            Assert.assertNull(jwe.getHeader("cty"));
        }

        // verify the nested token
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        int expGracePeriodSecs = 60;

        JwtConsumerBuilder builder = new JwtConsumerBuilder();

        // 'exp' must be available
        builder.setRequireExpirationTime();
        builder.setSkipDefaultAudienceValidation();
        // 'iat' must be available
        builder.setRequireIssuedAt();
        // 'RS256' is required
        builder.setJwsAlgorithmConstraints(
           new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, "RS256"));

        // issuer must be equal to TCKConstants.TEST_ISSUER
        builder.setExpectedIssuer(true, TCKConstants.TEST_ISSUER);
        builder.setVerificationKey(publicKey);
        builder.setAllowedClockSkewInSeconds(expGracePeriodSecs);

        JwtClaims claimsSet = builder.build().processToClaims(token);
        // Confirm all the claims available in /Token1.json have made it into the verified claimSet

        Assert.assertEquals(claimsSet.getClaimsMap().size(), 19);
        Assert.assertEquals(claimsSet.getIssuer(), "https://server.example.com");
        Assert.assertEquals(claimsSet.getJwtId(), "a-123");
        Assert.assertEquals(claimsSet.getSubject(), "24400320");
        Assert.assertEquals(claimsSet.getClaimValueAsString("upn"), "jdoe@example.com");
        Assert.assertEquals(claimsSet.getClaimValueAsString("preferred_username"), "jdoe");
        Assert.assertEquals(claimsSet.getAudience().size(), 1);
        Assert.assertEquals(claimsSet.getAudience().get(0), "s6BhdRkqt3");
        Assert.assertNotNull(claimsSet.getExpirationTime());
        long exp = claimsSet.getExpirationTime().getValue();
        Assert.assertEquals(claimsSet.getIssuedAt().getValue(), exp - 300);
        Assert.assertEquals(NumericDate.fromSeconds(claimsSet.getClaimValue("auth_time", Long.class)).getValue(),
                exp - 300);
        Assert.assertEquals(claimsSet.getClaimValueAsString("customString"), "customStringValue");
        Assert.assertEquals(claimsSet.getClaimValue("customInteger", Long.class), Long.valueOf(123456789));
        Assert.assertEquals(claimsSet.getClaimValue("customDouble", Double.class), 3.141592653589793);
        Assert.assertEquals(((List<?>)claimsSet.getClaimsMap().get("roles")).size(), 1);
        Assert.assertEquals(((List<?>)claimsSet.getClaimsMap().get("groups")).size(), 4);
        Assert.assertEquals(((List<?>)claimsSet.getClaimsMap().get("customStringArray")).size(), 3);
        Assert.assertEquals(((List<?>)claimsSet.getClaimsMap().get("customIntegerArray")).size(), 4);
        Assert.assertEquals(((List<?>)claimsSet.getClaimsMap().get("customDoubleArray")).size(), 5);
        Assert.assertEquals(((Map<?, ?>)claimsSet.getClaimsMap().get("customObject")).size(), 3);
    }
}
