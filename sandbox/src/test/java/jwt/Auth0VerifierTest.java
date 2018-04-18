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

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

public class Auth0VerifierTest extends AbstractVerifierTest {
    @Override
    protected void validateToken(String token, RSAPublicKey publicKey, String issuer, int expGracePeriodSecs) throws Exception {
        Algorithm algorithm = Algorithm.RSA256(publicKey, null);
        Verification builder = JWT.require(algorithm)
            .withIssuer(issuer);
        if(expGracePeriodSecs > 0) {
            builder = builder.acceptLeeway(expGracePeriodSecs);
        }
        JWTVerifier verifier = builder.build();
        DecodedJWT jwt = verifier.verify(token);
    }
}
