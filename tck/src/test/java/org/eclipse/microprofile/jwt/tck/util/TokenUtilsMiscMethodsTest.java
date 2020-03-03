/*
 * Copyright (c) 2016-2020 Contributors to the Eclipse Foundation
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
package org.eclipse.microprofile.jwt.tck.util;

import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_UTILS;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Validation of the TokenUtils methods
 */
public class TokenUtilsMiscMethodsTest {

    @Test(groups = TEST_GROUP_UTILS, description = "Used to generate a 2048 bit length key testing pair")
    public void testKeyPairGeneration2048Length() throws Exception {
        KeyPair keyPair = TokenUtils.generateKeyPair(2048);
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        Assert.assertEquals(privateKey.getModulus().bitLength(), 2048);
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        Assert.assertEquals(publicKey.getModulus().bitLength(), 2048);
    }

    @Test(groups = TEST_GROUP_UTILS, description = "Used to generate a 1024 bit length key testing pair")
    public void testKeyPairGeneration1024Length() throws Exception {
        KeyPair keyPair = TokenUtils.generateKeyPair(1024);
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        Assert.assertEquals(privateKey.getModulus().bitLength(), 1024);
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        Assert.assertEquals(publicKey.getModulus().bitLength(), 1024);
    }

    @Test(groups = TEST_GROUP_UTILS, description = "Test initial key validation")
    public void testReadPrivateKey() throws Exception {
        RSAPrivateKey privateKey = (RSAPrivateKey)TokenUtils.readPrivateKey("/privateKey.pem");
        Assert.assertEquals(privateKey.getModulus().bitLength(), 2048);
    }

    @Test(groups = TEST_GROUP_UTILS, description = "Test initial key validation")
    public void testReadPublicKey() throws Exception {
        RSAPublicKey publicKey = (RSAPublicKey) TokenUtils.readPublicKey("/publicKey.pem");
        Assert.assertEquals(publicKey.getModulus().bitLength(), 2048);
    }
}
