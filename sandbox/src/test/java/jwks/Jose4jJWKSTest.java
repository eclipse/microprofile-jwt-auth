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

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;

/**
 * Validate the jose4j JWT library
 * https://bitbucket.org/b_c/jose4j/overview
 */
public class Jose4jJWKSTest extends AbstractJWKSTest {
    @Override
    protected void validateToken(String token, URL jwksURL, String issuer, int expGracePeriodSecs) throws Exception {
        JwtConsumerBuilder builder = new JwtConsumerBuilder()
            .setRequireExpirationTime()
            .setRequireSubject()
            .setSkipDefaultAudienceValidation()
            .setExpectedIssuer(issuer)
            .setJwsAlgorithmConstraints(
                new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                                         AlgorithmIdentifiers.RSA_USING_SHA256));

        HttpsJwks keySource = new HttpsJwks(jwksURL.toExternalForm());
        builder.setVerificationKeyResolver(new HttpsJwksVerificationKeyResolver(keySource));

        if (expGracePeriodSecs > 0) {
            builder.setAllowedClockSkewInSeconds(expGracePeriodSecs);
        }
        else {
            builder.setEvaluationTime(NumericDate.fromSeconds(0));
        }

        JwtConsumer jwtConsumer = builder.build();
        JwtContext jwtContext = jwtConsumer.process(token);
        String type = jwtContext.getJoseObjects().get(0).getHeader("typ");
        //  Validate the JWT and process it to the Claims
        jwtConsumer.processContext(jwtContext);

    }
}
