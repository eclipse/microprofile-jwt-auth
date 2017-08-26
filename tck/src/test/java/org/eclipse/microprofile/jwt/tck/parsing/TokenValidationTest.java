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

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.TCKConstants;
import org.eclipse.microprofile.jwt.tck.util.ITokenParser;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.ServiceLoader;
import java.util.Set;

import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_JWT;

/**
 * Basic token parsing and validation tests for JWTPrincipal implementations
 */
public class TokenValidationTest {
    /** */
    private static ITokenParser tokenParser;
    /** */
    private static PublicKey publicKey;

    @BeforeClass(alwaysRun=true)
    public static void loadTokenParser() throws Exception {
        System.out.printf("TokenValidationTest.initClass\n");
        publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        if(publicKey == null) {
            throw new IllegalStateException("Failed to load /publicKey.pem resource");
        }

        // Load a
        ServiceLoader<ITokenParser> serviceLoader = ServiceLoader.load(ITokenParser.class);
        if(serviceLoader.iterator().hasNext() == false) {
            throw new IllegalStateException(String.format("An %s service provider is required", ITokenParser.class.getName()));
        }
        tokenParser = serviceLoader.iterator().next();
        if(tokenParser == null) {
            throw new IllegalStateException(String.format("Service provider for %s  produced a null parser", ITokenParser.class.getName()));
        }
        System.out.printf("Using ITokenParser: %s\n", tokenParser);
    }

    /**
     * Create a JWT token representation of the testJWTCallerPrincipal.json test
     * resource and then parse it into a JWTPrincipal to validate the
     * container's implementation.
     *
     * @throws Exception on parse failure
     */
    @Test(groups = TEST_GROUP_JWT,
        description = "validate the JsonWebToken returned by ITokenParser")
    public void testJWTCallerPrincipal() throws Exception {
        long nowInSeconds = System.currentTimeMillis() / 1000;
        HashMap<String, Long> timeClaims = new HashMap<>();
        String jwt = TokenUtils.generateTokenString("/testJWTCallerPrincipal.json", null, timeClaims);
        System.out.printf("jwt: %s\n", jwt);
        long iatClaim = timeClaims.get(Claims.iat.name());
        Long authTimeClaim = timeClaims.get(Claims.auth_time.name());
        long expClaim = timeClaims.get(Claims.exp.name());

        JsonWebToken jwtPrincipal = tokenParser.parse(jwt, TCKConstants.TEST_ISSUER, publicKey);
        System.out.printf("Parsed caller principal: %s\n", jwtPrincipal);

        // Validate the required claims
        Assert.assertEquals(jwt, jwtPrincipal.getRawToken(), "bearer_token");
        Assert.assertEquals("https://server.example.com", jwtPrincipal.getIssuer(), "iss");
        Assert.assertEquals("24400320", jwtPrincipal.getSubject(), "sub");
        Assert.assertEquals("s6BhdRkqt3", jwtPrincipal.getAudience().toArray()[0], "aud");
        Assert.assertEquals("jdoe@example.com", jwtPrincipal.getName(), "name");
        Assert.assertEquals("a-123", jwtPrincipal.getTokenID(), "jti");
        Assert.assertEquals(expClaim, jwtPrincipal.getExpirationTime());
        Assert.assertEquals(iatClaim, jwtPrincipal.getIssuedAtTime());

        // Validate the groups
        Set<String> groups = jwtPrincipal.getGroups();
        String[] expectedGroupNames = {"group1", "group2", "role-in-realm", "user", "manager"};
        HashSet<String> missingGroups = new HashSet<>();
        for (String group : expectedGroupNames) {
            if(!groups.contains(group)) {
                missingGroups.add(group);
            }
        }
        if(missingGroups.size() > 0) {
            Assert.fail("There are missing groups: "+missingGroups);
        }

        // Validate other claims
        Object authTime = jwtPrincipal.getClaim("auth_time");
        Assert.assertTrue(authTime instanceof Number, "auth_time is a Number");
        Assert.assertTrue(nowInSeconds <= ((Number)authTime).intValue(), "auth_time as int is >= nowInSeconds");

        String preferredName = jwtPrincipal.getClaim("preferred_username");
        Assert.assertEquals("jdoe", preferredName, "preferred_username is jdoe");
    }

    /**
     * Validate that the updates jwt-content1.json verifies against current time
     * @throws Exception - thrown are parse failure
     * @see TokenUtils#generateTokenString(String)
     */
    @Test(groups = TCKConstants.TEST_GROUP_UTILS, description = "Internal test to validate the behavior of TokenUtils.generateTokenString")
    public void testUtilsToken() throws Exception {
        long nowSec = System.currentTimeMillis() / 1000;
        String jwt = TokenUtils.generateTokenString("/jwt-content1.json");
        JsonWebToken callerPrincipal = tokenParser.parse(jwt, TCKConstants.TEST_ISSUER, publicKey);
        System.out.println(callerPrincipal);
        long iss = callerPrincipal.getIssuedAtTime();
        Assert.assertTrue((nowSec - iss) < 1, String.format("now(%d) < 1s from iss(%d)", nowSec, iss));
        long exp = callerPrincipal.getExpirationTime();
        Assert.assertTrue((exp - nowSec) > 299, String.format("now(%d) > 299s from exp(%d)", nowSec, exp));
    }

    /**
     * Validate that a token that is past it's exp claim should fail the parse verification
     * @throws Exception - expect a Exception
     */
    @Test(groups = TEST_GROUP_JWT, description = "Validate that a token that is past exp claim should fail the parse verification")
    public void testExpiredValidation() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.EXP);
        String jwt = TokenUtils.generateTokenString("/jwt-content1.json", invalidFields);
        try {
            JsonWebToken callerPrincipal = tokenParser.parse(jwt, TCKConstants.TEST_ISSUER, publicKey);
            Assert.fail("Was able to parse the token: " + callerPrincipal);
        }
        catch (Exception e) {
            Throwable cause = e.getCause();
            System.out.printf("Failed as expected with cause: %s\n", cause.getMessage());
        }
    }

    /**
     * Validate that if an issuer other than {@link TCKConstants#TEST_ISSUER} is
     * used on the token, the token fails to validate
     * @throws Exception thrown on unexpected error
     */
    @Test(groups = TEST_GROUP_JWT, description = "Validate the token fails to validate when using an invalid issuer")
    public void testBadIssuer() throws Exception {
        // Indicate that TokenUtils should overwrite the issuer with "INVALID_ISSUER"
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.ISSUER);
        String jwt = TokenUtils.generateTokenString("/jwt-content1.json", invalidFields);
        PublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        try {
            JsonWebToken callerPrincipal = tokenParser.parse(jwt, TCKConstants.TEST_ISSUER, publicKey);
            Assert.fail("Was able to parse the token: " + callerPrincipal);
        }
        catch (Exception e) {
            Throwable cause = e.getCause();
            System.out.printf("Failed as expected with cause: %s\n", cause.getMessage());
        }
    }

    @Test(groups = TEST_GROUP_JWT, description = "Validate the token fails to validate when using an invalid signer")
    public void testBadSigner() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.SIGNER);
        String jwt = TokenUtils.generateTokenString("/jwt-content1.json", invalidFields);
        try {
            JsonWebToken callerPrincipal = tokenParser.parse(jwt, TCKConstants.TEST_ISSUER, publicKey);
            Assert.fail("Was able to parse the token: " + callerPrincipal);
        }
        catch (Exception e) {
            Throwable cause = e.getCause();
            System.out.printf("Failed as expected with cause: %s\n", cause.getMessage());
        }
    }
}
