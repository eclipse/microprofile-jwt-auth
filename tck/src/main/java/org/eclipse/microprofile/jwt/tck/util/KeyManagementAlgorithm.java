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
package org.eclipse.microprofile.jwt.tck.util;

public enum KeyManagementAlgorithm {
    /**
     * RSAES using Optimal Asymmetric Encryption Padding with SHA-1
     */
    RSA_OAEP,
    /**
     * RSAES using Optimal Asymmetric Encryption Padding with SHA-256
     */
    RSA_OAEP_256;

    public String getAlgorithm() {
        return name().replace("_", "-");
    }
}
