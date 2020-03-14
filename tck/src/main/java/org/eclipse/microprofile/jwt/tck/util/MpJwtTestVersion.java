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
package org.eclipse.microprofile.jwt.tck.util;

/**
 * An enum used to identify which version of the MP-JWT a TCK test war is
 * targeting. The target version can be found by loading the META-INF/MPJWTTESTVERSION
 * resource from the test war and converting it to the MpJwtTestVersion value.
 */
public enum MpJwtTestVersion {
    MPJWT_V_1_0,
    MPJWT_V_1_1
    ;

    public static final String VERSION_LOCATION = "META-INF/MPJWTTESTVERSION";
    public static final String MANIFEST_NAME = "MPJWTTESTVERSION";
}
