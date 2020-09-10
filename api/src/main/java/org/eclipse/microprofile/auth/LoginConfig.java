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
package org.eclipse.microprofile.auth;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * A security annotation describing the authentication method and the associated realm name that
 * should be used for this application.
 *
 * Note: this annotation may be removed in the future versions of the MP JWT specification.
 *
 */
@Inherited
@Documented
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface LoginConfig {
    /**
     * The 'authMethod' is used to configure the "MP-JWT" authentication mechanism for the
     * JAX-RS application. As a prerequisite to gaining access to any web resources
     * which are protected by an authorization constraint, a user must have
     * authenticated using the configured mechanism.
     * Support for the other authentication mechanisms is optional.
     *
     * @return the configured auth-method
     */
    String authMethod();

    /**
     * The realm name
     *
     * @return the realm name which may be empty
     */
    String realmName() default "";
}
