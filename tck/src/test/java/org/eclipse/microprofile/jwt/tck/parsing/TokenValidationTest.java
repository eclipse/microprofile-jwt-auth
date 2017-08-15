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

import org.eclipse.microprofile.jwt.JWTPrincipal;
import org.eclipse.microprofile.jwt.tck.util.ITokenParser;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jboss.arquillian.junit.Arquillian;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.PublicKey;
import java.util.HashSet;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * Basic token parsing and validation tests for JWTPrincipal implementations
 */
@RunWith(Arquillian.class)
public class TokenValidationTest {
    private static final String TEST_ISSUER = "https://server.example.com";
    /** */
    private static ITokenParser tokenParser;
    /** */
    private static PublicKey publicKey;

    @BeforeClass
    public static void initClass() throws Exception {
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
    }

    /**
     * Create a JWT token representation of the testRIJWTCallerPrincipal.json test resource and then parse it into a
     * JWTPrincipal to validate the container's implementation.
     *
     * @throws Exception
     */
    @Test
    public void testRIJWTCallerPrincipal() throws Exception {
        long nowInSeconds = System.currentTimeMillis() / 1000;
        String jwt = TokenUtils.generateTokenString("/testRIJWTCallerPrincipal.json");
        System.out.printf("jwt: %s\n", jwt);
        JWTPrincipal jwtPrincipal = tokenParser.parse(jwt, TEST_ISSUER, publicKey);
        System.out.printf("Parsed caller principal: %s\n", jwtPrincipal);

        // Validate the required claims
        Assert.assertEquals("bearer_token", jwt, jwtPrincipal.getRawToken());
        Assert.assertEquals("iss", "https://server.example.com", jwtPrincipal.getIssuer());
        Assert.assertEquals("sub", "24400320", jwtPrincipal.getSubject());
        Assert.assertEquals("aud", "s6BhdRkqt3", jwtPrincipal.getAudience().toArray()[0]);
        Assert.assertEquals("name", "jdoe@example.com", jwtPrincipal.getName());
        Assert.assertEquals("jti", "a-123", jwtPrincipal.getTokenID());
        Assert.assertTrue("exp is > nowInSeconds", jwtPrincipal.getExpirationTime() > nowInSeconds);
        Assert.assertTrue("iat is >= nowInSeconds", jwtPrincipal.getIssuedAtTime() >= nowInSeconds);

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
        Assert.assertTrue("auth_time is a Number", authTime instanceof Number);
        Assert.assertTrue("auth_time as int is >= nowInSeconds", nowInSeconds <= ((Number)authTime).intValue());

        String preferredName = (String) jwtPrincipal.getClaim("preferred_username");
        Assert.assertEquals("preferred_username is jdoe", "jdoe", preferredName);
    }

    /**
     * Validate that the updates jwt-content1.json verifies against current time
     * @throws Exception - thrown are parse failure
     * @see TokenUtils#generateTokenString(String)
     */
    @Test
    @Ignore("Internal test to validate the behavior of TokenUtils.generateTokenString")
    public void testUtilsToken() throws Exception {
        String jwt = TokenUtils.generateTokenString("/jwt-content1.json");
        JWTPrincipal callerPrincipal = tokenParser.parse(jwt, TEST_ISSUER, publicKey);
        System.out.println(callerPrincipal);
        long nowSec = System.currentTimeMillis() / 1000;
        long iss = callerPrincipal.getIssuedAtTime();
        Assert.assertTrue(String.format("now(%d) < 1s from iss(%d)", nowSec, iss), (nowSec - iss) < 1);
        long exp = callerPrincipal.getExpirationTime();
        Assert.assertTrue(String.format("now(%d) > 299s from exp(%d)", nowSec, exp), (exp - nowSec) > 299);
    }

    /**
     * Validate that a token that is past is exp claim should fail the parse verification
     * @throws Exception - expect a Exception
     */
    @Test()
    public void testExpiredValidation() throws Exception {
        HashSet<TokenUtils.InvalidFields> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidFields.EXP);
        String jwt = TokenUtils.generateTokenString("/jwt-content1.json", invalidFields);
        try {
            JWTPrincipal callerPrincipal = tokenParser.parse(jwt, TEST_ISSUER, publicKey);
            Assert.fail("Was able to parse the token: " + callerPrincipal);
        }
        catch (Exception e) {
            Throwable cause = e.getCause();
            System.out.printf("Failed as expected with cause: %s\n", cause.getMessage());
        }
    }

    /**
     * Validate that if an issuer other than {@link #TEST_ISSUER} is used on the token, the token fails to validate
     * @throws Exception thrown on unexpected error
     */
    @Test
    public void testBadIssuer() throws Exception {
        // Indicate that TokenUtils should overwrite the issuer with "INVALID_ISSUER"
        HashSet<TokenUtils.InvalidFields> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidFields.ISSUER);
        String jwt = TokenUtils.generateTokenString("/jwt-content1.json", invalidFields);
        PublicKey publicKey = TokenUtils.readPublicKey("/publicKey.pem");
        try {
            JWTPrincipal callerPrincipal = tokenParser.parse(jwt, TEST_ISSUER, publicKey);
            Assert.fail("Was able to parse the token: " + callerPrincipal);
        }
        catch (Exception e) {
            Throwable cause = e.getCause();
            System.out.printf("Failed as expected with cause: %s\n", cause.getMessage());
        }
    }

    @Test
    public void testBadSigner() throws Exception {
        HashSet<TokenUtils.InvalidFields> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidFields.SIGNER);
        String jwt = TokenUtils.generateTokenString("/jwt-content1.json", invalidFields);
        try {
            JWTPrincipal callerPrincipal = tokenParser.parse(jwt, TEST_ISSUER, publicKey);
            Assert.fail("Was able to parse the token: " + callerPrincipal);
        }
        catch (Exception e) {
            Throwable cause = e.getCause();
            System.out.printf("Failed as expected with cause: %s\n", cause.getMessage());
        }
    }

}
