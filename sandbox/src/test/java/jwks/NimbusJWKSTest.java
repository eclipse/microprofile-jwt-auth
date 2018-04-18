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

import java.net.URL;
import java.util.Date;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 * Validate the Nimbus JWT library
 * https://connect2id.com/products/nimbus-jose-jwt
 */
public class NimbusJWKSTest extends AbstractJWKSTest {
    /**
     * Demonstrate how to handle a JWKS URL with Nimbus
     *
     * @param token - the signed, base64 encoded header.content.sig JWT string
     * @param jwksURL - URL to a JWKS that contains the public key to verify the JWT signature
     * @param issuer - the expected iss claim value
     * @param expGracePeriodSecs - grace period in seconds for evaluating the exp claim
     * @throws Exception
     */
    @Override
    protected void validateToken(String token, URL jwksURL, String issuer, int expGracePeriodSecs) throws Exception {
        // Parse the token
        SignedJWT signedJWT = SignedJWT.parse(token);

        // Add verifiers for the issuer and expiration date
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWTClaimsSetVerifier((claimsSet, context) -> {
            // iss
            String iss = claimsSet.getIssuer();
            if (iss == null || ! iss.equals(issuer)) {
                System.err.printf("issuer(%s) != %s\n", iss, issuer);
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
        // Use the JWKS URL and require the RS256 signing algorithm
        RemoteJWKSet<SecurityContext> keySource = new RemoteJWKSet<>(jwksURL);
        JWSKeySelector<SecurityContext> authContextKeySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keySource);
        jwtProcessor.setJWSKeySelector(authContextKeySelector);
        jwtProcessor.process(signedJWT, null);

        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        System.out.printf("Validated JWT, claimsSet: %s\n", claimsSet);
    }
}
