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

import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.tck.TCKConstants;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Tests which verify TokenUtils generateTokenString methods
 */
public class TokenUtilsTest {

    @Test(groups = TCKConstants.TEST_GROUP_UTILS, expectedExceptions = {InvalidJwtException.class},
            description = "Illustrate validation of alg")
    public void testFailAlgorithm() throws Exception {
        Set<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.ALG);
        String token = TokenUtils.signClaims("/Token1.json", invalidFields);
        validateToken(token);
    }
    
    @Test(groups = TCKConstants.TEST_GROUP_UTILS, expectedExceptions = {InvalidJwtException.class},
            description = "Deprecated: Illustrate validation of alg")
    public void testFailAlgorithmDeprecated() throws Exception {
        Set<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.ALG);
        @SuppressWarnings("deprecation")
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);
        validateToken(token);
    }

    @Test(groups = TCKConstants.TEST_GROUP_UTILS, description = "Illustrate validation of a JWT")
    public void testValidToken() throws Exception {
        String token = TokenUtils.signClaims("/Token1.json");
        validateToken(token);
    }
    
    @Test(groups = TCKConstants.TEST_GROUP_UTILS, description = "Deprecated: Illustrate validation of a JWT")
    public void testValidTokenDeprecated() throws Exception {
        @SuppressWarnings("deprecation")
        String token = TokenUtils.generateTokenString("/Token1.json");
        validateToken(token);
    }

    @Test(groups = TCKConstants.TEST_GROUP_UTILS, expectedExceptions = {InvalidJwtException.class},
            description = "Illustrate validation of issuer")
    public void testFailIssuer() throws Exception {
        Set<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.ISSUER);
        String token = TokenUtils.signClaims("/Token1.json", invalidFields);
        validateToken(token);
    }
    
    @Test(groups = TCKConstants.TEST_GROUP_UTILS, expectedExceptions = {InvalidJwtException.class},
            description = "Deprecated: Illustrate validation of issuer")
    public void testFailIssuerDeprecated() throws Exception {
        Set<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.ISSUER);
        @SuppressWarnings("deprecation")
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);
        validateToken(token);
    }

    @Test(groups = TCKConstants.TEST_GROUP_UTILS, expectedExceptions = {InvalidJwtException.class},
        description = "Illustrate validation of signer")
    public void testFailSignature() throws Exception {
        Set<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.SIGNER);
        String token = TokenUtils.signClaims("/Token1.json", invalidFields);
        validateToken(token);
    }
    
    @Test(groups = TCKConstants.TEST_GROUP_UTILS, expectedExceptions = {InvalidJwtException.class},
            description = "Deprecated: Illustrate validation of signer")
    public void testFailSignatureDeprecated() throws Exception {
        Set<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.SIGNER);
        @SuppressWarnings("deprecation")
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);
        validateToken(token);
    }

    @Test(groups = TCKConstants.TEST_GROUP_UTILS, expectedExceptions = {InvalidJwtException.class},
        description = "Illustrate validation of exp")
    public void testFailExpired() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        Set<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.EXP);
        String token = TokenUtils.signClaims("/Token1.json", invalidFields, timeClaims);
        validateToken(token);
    }
    
    @Test(groups = TCKConstants.TEST_GROUP_UTILS, expectedExceptions = {InvalidJwtException.class},
            description = "Deprecated: Illustrate validation of exp")
    public void testFailExpiredDeprecated() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        Set<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.EXP);
        @SuppressWarnings("deprecation")
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields, timeClaims);
        validateToken(token);
    }

    @Test(groups = TCKConstants.TEST_GROUP_UTILS, expectedExceptions = {InvalidJwtException.class},
        description = "Illustrate validation of exp that has just expired")
    public void testFailJustExpired() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        // Set exp to 61 seconds in past
        long exp = TokenUtils.currentTimeInSecs() - 61;
        timeClaims.put(Claims.exp.name(), exp);
        String token = TokenUtils.signClaims("/Token1.json", null, timeClaims);
        validateToken(token);
    }
    
    @Test(groups = TCKConstants.TEST_GROUP_UTILS, expectedExceptions = {InvalidJwtException.class},
            description = "Deprecated: Illustrate validation of exp that has just expired")
    public void testFailJustExpiredDeprecated() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        // Set exp to 61 seconds in past
        long exp = TokenUtils.currentTimeInSecs() - 61;
        timeClaims.put(Claims.exp.name(), exp);
        @SuppressWarnings("deprecation")
        String token = TokenUtils.generateTokenString("/Token1.json", null, timeClaims);
        validateToken(token);
    }

    @Test(groups = TCKConstants.TEST_GROUP_UTILS,
        description = "Illustrate validation of exp that is in grace period")
    public void testExpGrace() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        // Set exp to 45 seconds in past
        long exp = TokenUtils.currentTimeInSecs() - 45;
        timeClaims.put(Claims.exp.name(), exp);
        String token = TokenUtils.signClaims("/Token1.json", null, timeClaims);
        validateToken(token, exp);
    }
    
    @Test(groups = TCKConstants.TEST_GROUP_UTILS,
            description = "Deprecated: Illustrate validation of exp that is in grace period")
    public void testExpGraceDeprecated() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        // Set exp to 45 seconds in past
        long exp = TokenUtils.currentTimeInSecs() - 45;
        timeClaims.put(Claims.exp.name(), exp);
        @SuppressWarnings("deprecation")
        String token = TokenUtils.generateTokenString("/Token1.json", null, timeClaims);
        validateToken(token, exp);
    }

    private void validateToken(String token) throws Exception {
        validateToken(token, null);
    }
    private void validateToken(String token, Long expectedExpValue) throws Exception {

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
        if (expectedExpValue != null) {
            Assert.assertEquals(claimsSet.getExpirationTime().getValue(), (long)expectedExpValue);
            Assert.assertEquals(claimsSet.getIssuedAt().getValue(), expectedExpValue - 5);
            Assert.assertEquals(NumericDate.fromSeconds(claimsSet.getClaimValue("auth_time", Long.class)).getValue(),
                    expectedExpValue - 5);
        }
        else {
            Assert.assertNotNull(claimsSet.getExpirationTime());
            long exp = claimsSet.getExpirationTime().getValue();
            Assert.assertEquals(claimsSet.getIssuedAt().getValue(), exp - 300);
            Assert.assertEquals(NumericDate.fromSeconds(claimsSet.getClaimValue("auth_time", Long.class)).getValue(),
                    exp - 300);
        }

        Assert.assertEquals(claimsSet.getClaimValueAsString("customString"), "customStringValue");
        Assert.assertEquals(claimsSet.getClaimValue("customInteger", Long.class), Long.valueOf(123456789));
        Assert.assertEquals(claimsSet.getClaimValue("customDouble", Double.class), 3.141592653589793);
        Assert.assertTrue(claimsSet.getClaimValue("customBoolean", Boolean.class));
        Assert.assertEquals(((List<?>)claimsSet.getClaimsMap().get("roles")).size(), 1);
        Assert.assertEquals(((List<?>)claimsSet.getClaimsMap().get("groups")).size(), 4);
        Assert.assertEquals(((List<?>)claimsSet.getClaimsMap().get("customStringArray")).size(), 3);
        Assert.assertEquals(((List<?>)claimsSet.getClaimsMap().get("customIntegerArray")).size(), 4);
        Assert.assertEquals(((List<?>)claimsSet.getClaimsMap().get("customDoubleArray")).size(), 5);
        Assert.assertEquals(((Map<?, ?>)claimsSet.getClaimsMap().get("customObject")).size(), 3);
    }
}
