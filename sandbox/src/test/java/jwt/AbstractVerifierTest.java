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
package jwt;

import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.HashSet;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jwt.proc.BadJWTException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.IncorrectClaimException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.InvalidJwtSignatureException;
import org.testng.annotations.Test;


public abstract class AbstractVerifierTest {
    public static final String TEST_ISSUER = "https://server.example.com";

    @Test
    public void testValidToken() throws Exception {
        String token = TokenUtils.generateTokenString("/Token1.json");
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        int expGracePeriodSecs = 60;
        validateToken(token, publicKey, TEST_ISSUER, expGracePeriodSecs);
    }
    @Test(expectedExceptions = {BadJWTException.class, InvalidJwtException.class, InvalidClaimException.class, IncorrectClaimException.class},
        description = "Illustrate validation of issuer")
    public void testBadIssuer() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.ISSUER);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        int expGracePeriodSecs = 60;
        validateToken(token, publicKey, TEST_ISSUER, expGracePeriodSecs);
    }
    @Test(expectedExceptions = {BadJWSException.class, SignatureVerificationException.class,
        InvalidJwtSignatureException.class, SignatureException.class},
        description = "Illustrate validation of signer")
    public void testFailSignature() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.SIGNER);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        int expGracePeriodSecs = 60;
        validateToken(token, publicKey, TEST_ISSUER, expGracePeriodSecs);
    }
    @Test(expectedExceptions = {JOSEException.class, AlgorithmMismatchException.class, InvalidJwtException.class, UnsupportedJwtException.class},
        description = "Illustrate validation of signature algorithm")
    public void testFailSignatureAlgorithm() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.ALG);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        int expGracePeriodSecs = 60;
        validateToken(token, publicKey, TEST_ISSUER, expGracePeriodSecs);
    }
    @Test(expectedExceptions = {BadJWTException.class, InvalidJwtException.class, TokenExpiredException.class, ExpiredJwtException.class},
        description = "Illustrate validation of exp")
    public void testFailExpired() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.EXP);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields, timeClaims);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        int expGracePeriodSecs = 60;
        validateToken(token, publicKey, TEST_ISSUER, expGracePeriodSecs);
    }
    @Test(description = "Illustrate validation of exp that is in grace period")
    public void testExpGrace() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        // Set exp to 45 seconds in past
        long exp = TokenUtils.currentTimeInSecs() - 45;
        timeClaims.put(Claims.exp.name(), exp);
        String token = TokenUtils.generateTokenString("/Token1.json", null, timeClaims);
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        int expGracePeriodSecs = 60;
        validateToken(token, publicKey, TEST_ISSUER, expGracePeriodSecs);
    }
    /**
     *
     * @param token - the signed, base64 encoded header.content.sig JWT string
     * @param publicKey - the public key to verify the expected signature
     * @param issuer - the expected iss claim value
     * @param expGracePeriodSecs - grace period in seconds for evaluating the exp claim
     * @throws Exception
     */
    abstract protected void validateToken(String token, RSAPublicKey publicKey, String issuer, int expGracePeriodSecs)
        throws Exception;
}
