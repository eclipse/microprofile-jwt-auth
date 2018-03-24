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
package org.eclipse.microprofile.jwt.tck.parsing;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.tck.TCKConstants;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;

/**
 * Internal debugging tests
 */
public class DebugTest {
    @Test(groups = TCKConstants.TEST_GROUP_DEBUG,
        description = "Validate how to use the HS256 signature alg")
    public void testHS256() throws Exception {
        JWTClaimsSet claimsSet = JWTClaimsSet.parse("{\"sub\":\"jdoe\"}");
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        SecureRandom random = new SecureRandom();
        BigInteger secret = BigInteger.probablePrime(256, random);
        JWSSigner signer = new MACSigner(secret.toByteArray());
        signedJWT.sign(signer);
    }

    @Test(groups = TCKConstants.TEST_GROUP_DEBUG,
        description = "Illustrate validation of a JWT using the nimbus library")
    public void testNimbusValidation() throws Exception {
        String token = TokenUtils.generateTokenString("/Token1.json");
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        int expGracePeriodSecs = 60;
        validateToken(token, publicKey, expGracePeriodSecs);
    }

    @Test(groups = TCKConstants.TEST_GROUP_DEBUG, expectedExceptions = {BadJWTException.class},
        description = "Illustrate validation of iss")
    public void testNimbusFailIssuer() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.ISSUER);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        int expGracePeriodSecs = 60;
        validateToken(token, publicKey, expGracePeriodSecs);
    }

    @Test(groups = TCKConstants.TEST_GROUP_DEBUG, expectedExceptions = {BadJWSException.class},
        description = "Illustrate validation of signer")
    public void testNimbusFailSignature() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.SIGNER);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        int expGracePeriodSecs = 60;
        validateToken(token, publicKey, expGracePeriodSecs);
    }

    @Test(groups = TCKConstants.TEST_GROUP_DEBUG, expectedExceptions = {BadJWTException.class},
        description = "Illustrate validation of exp")
    public void testNimbusFailExpired() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.EXP);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields, timeClaims);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        int expGracePeriodSecs = 60;
        validateToken(token, publicKey, expGracePeriodSecs);
    }

    @Test(groups = TCKConstants.TEST_GROUP_DEBUG, expectedExceptions = {BadJWTException.class},
        description = "Illustrate validation of exp that has just expired")
    public void testNimbusFailJustExpired() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        // Set exp to 61 seconds in past
        long exp = TokenUtils.currentTimeInSecs() - 61;
        timeClaims.put(Claims.exp.name(), exp);
        String token = TokenUtils.generateTokenString("/Token1.json", null, timeClaims);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        int expGracePeriodSecs = 60;
        validateToken(token, publicKey, expGracePeriodSecs);
    }

    @Test(groups = TCKConstants.TEST_GROUP_DEBUG,
        description = "Illustrate validation of exp that is in grace period")
    public void testNimbusExpGrace() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        // Set exp to 45 seconds in past
        long exp = TokenUtils.currentTimeInSecs() - 45;
        timeClaims.put(Claims.exp.name(), exp);
        String token = TokenUtils.generateTokenString("/Token1.json", null, timeClaims);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        int expGracePeriodSecs = 60;
        validateToken(token, publicKey, expGracePeriodSecs);
    }

    private void validateToken(String token, RSAPublicKey publicKey, int expGracePeriodSecs) throws Exception {
        SignedJWT signedJWT = SignedJWT.parse(token);
        // Validate the signature
        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        signedJWT.verify(verifier);

        // Add verifiers for the issuer and expiration date
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWTClaimsSetVerifier((claimsSet, context) -> {
            // iss
            String issuer = claimsSet.getIssuer();
            if (issuer == null || ! issuer.equals(TCKConstants.TEST_ISSUER)) {
                System.err.printf("issuer(%s) != %s\n", issuer, TCKConstants.TEST_ISSUER);
                throw new BadJWTException("Invalid token issuer");
            }
            // exp
            if(expGracePeriodSecs > 0) {
                Date expMS = null;
                try {
                    // Nimbus coverts long exp to a Date
                    expMS = claimsSet.getDateClaim("exp");
                }
                catch (java.text.ParseException e) {
                    System.err.printf("Failed to get exp claim\n");
                    e.printStackTrace();
                    throw new BadJWTException("Failed to get exp claim", e);
                }
                long now = System.currentTimeMillis();
                // The exp claim needs to be > now - grace period
                long expUpperMS = now - expGracePeriodSecs * 1000;
                // Fail if expMS is not in the future adjusted for grace period
                if (expUpperMS > expMS.getTime()) {
                    System.err.printf("exp(%d) < upper bound(%d)\n", expMS.getTime(), expUpperMS);
                    throw new BadJWTException("Token is expired");
                }
            }
        });
        // The signing algorithm must be RS256
        JWSKeySelector<SecurityContext> authContextKeySelector = (header, context) -> {
            if(header.getAlgorithm() != JWSAlgorithm.RS256) {
                throw new KeySourceException("RS256 algorithm not specified");
            }
            return Collections.singletonList(publicKey);
        };
        jwtProcessor.setJWSKeySelector(authContextKeySelector);
        jwtProcessor.process(signedJWT, null);

        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        System.out.printf("Validated JWT, claimsSet: %s\n", claimsSet);
    }
}
