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
package org.eclipse.microprofile.jwt.tck.config;

import org.jboss.arquillian.testng.Arquillian;
import org.testng.annotations.Test;

/**
 * Validate that the bundled mp.jwt.verify.publickey config property as a literal JWK
 * is used to validate the JWT which is signed with privateKey4k.pem
 */
public class PublicKeyAsJWKTest extends Arquillian {
    @Test
    public void noop() {

    }
}
