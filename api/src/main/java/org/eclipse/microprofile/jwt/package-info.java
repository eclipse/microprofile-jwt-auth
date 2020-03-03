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

/**
 * <p>Interoperable JWT RBAC for Microprofile
 *
 * <h2>Overview</h2>
 * This package contains the primary interfaces and support classes for the JSON Web Tokens(JWT) for role based
 * access control(RBAC) of MicroProfile microservice endpoints. The primary class is the JsonWebToken interface
 * that defines the view of the current authenticated user and associated JWT claims. It is available for injection
 * as well as the user principal available from the container security API.
 *
 * The supporting classes in this package include:
 * <ul>
 *     <li>Claim: a qualifier annotation used to mark a JWT claim value injection point</li>
 *     <li>Claims: this is an enum that defines the names and types of the JWT claims standardized through
 *     RFC7519, OIDC, etc.</li>
 *     <li>ClaimValue: this is a proxyable/injectable interface that represents the value of a single JWT claim.</li>
 * </ul>
 *
 *
 */
@org.osgi.annotation.versioning.Version("1.1")
package org.eclipse.microprofile.jwt;
