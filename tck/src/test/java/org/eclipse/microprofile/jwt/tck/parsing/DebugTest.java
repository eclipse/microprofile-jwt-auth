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
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.microprofile.jwt.tck.TCKConstants;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

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
}
