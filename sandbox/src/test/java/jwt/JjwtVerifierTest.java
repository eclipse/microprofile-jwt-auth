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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;

public class JjwtVerifierTest extends AbstractVerifierTest {
    @Override
    protected void validateToken(String token, RSAPublicKey publicKey, String issuer, int expGracePeriodSecs) throws Exception {
        JwtParser parser = Jwts.parser()
            .setSigningKey(publicKey)
            .requireIssuer(issuer)
            ;
        if(expGracePeriodSecs > 0) {
            parser = parser.setAllowedClockSkewSeconds(expGracePeriodSecs);
        }

        Jwt jwt = parser.parse(token);
        String alg = jwt.getHeader().get("alg").toString();
        if(alg == null || !alg.equals(SignatureAlgorithm.RS256.getValue())) {
            throw new SignatureException("Non-RS256 alg: "+alg);
        }
        Jws<Claims> claims = parser.parseClaimsJws(token);
    }
}
