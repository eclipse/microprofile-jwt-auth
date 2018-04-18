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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.auth0.jwt.interfaces.Verification;

/**
 * Validate the auth0 jwt library
 * https://github.com/auth0/java-jwt
 */
public class Auth0JWKSTest extends AbstractJWKSTest {
    @Override
    protected void validateToken(String token, URL jwksURL, String issuer, int expGracePeriodSecs) throws Exception {
        JwkProvider jwkStore = new UrlJwkProvider(jwksURL);
        RSAKeyProvider keyProvider = new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String kid) throws JWTVerificationException {
                //Received 'kid' value might be null if it wasn't defined in the Token's header
                RSAPublicKey publicKey = null;
                try {
                    Jwk jwk = jwkStore.get(kid);
                    publicKey = (RSAPublicKey) jwk.getPublicKey();
                    return publicKey;
                }
                catch (Exception e) {
                    throw new JWTVerificationException("Failed to retrieve key", e);
                }
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return null;
            }

            @Override
            public String getPrivateKeyId() {
                return null;
            }
        };
        Algorithm algorithm = Algorithm.RSA256(keyProvider);

        Verification builder = JWT.require(algorithm)
            .withIssuer(issuer);
        if(expGracePeriodSecs > 0) {
            builder = builder.acceptLeeway(expGracePeriodSecs);
        }
        JWTVerifier verifier = builder.build();
        DecodedJWT jwt = verifier.verify(token);
    }
}
