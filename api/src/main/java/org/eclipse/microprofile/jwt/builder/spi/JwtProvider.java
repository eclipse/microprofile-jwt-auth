/*
 * Copyright (c) 2020 Contributors to the Eclipse Foundation
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
package org.eclipse.microprofile.jwt.builder.spi;

import java.util.Iterator;
import java.util.Map;
import java.util.ServiceLoader;

import org.eclipse.microprofile.jwt.builder.JwtClaimsBuilder;
import org.eclipse.microprofile.jwt.builder.JwtException;

/**
 * Service provider for JWT Claims Builder objects.
 *
 * @see ServiceLoader
 */
public abstract class JwtProvider {
    /**
     * Name of the default {@code JwtProvider} implementation class.
     */
    private static final String DEFAULT_JWT_PROVIDER = "io.smallrye.jwt.build.impl.JwtProviderImpl";

    protected JwtProvider() {
    }

    /**
     * Creates a JWT provider object. The provider is loaded using the
     * {@link ServiceLoader#load(Class)} method. If there are no available
     * service providers, this method returns the default service provider.
     * Users are recommended to cache the result of this method.
     *
     * @see ServiceLoader
     * @return a JWT provider
     */
    public static JwtProvider provider() {
        ServiceLoader<JwtProvider> loader = ServiceLoader.load(JwtProvider.class);
        Iterator<JwtProvider> it = loader.iterator();
        if (it.hasNext()) {
            return it.next();
        }
        try {
            return (JwtProvider) Class.forName(DEFAULT_JWT_PROVIDER).newInstance();
        } 
        catch (ClassNotFoundException ex) {
            throw new JwtException(
                    "JwtProvider " + DEFAULT_JWT_PROVIDER + " has not been found", ex);
        } 
        catch (IllegalAccessException ex) {
            throw new JwtException(
                    "JwtProvider " + DEFAULT_JWT_PROVIDER + " class could not be accessed: " + ex, ex);
        } 
        catch (InstantiationException ex) {
            throw new JwtException(
                    "JwtProvider " + DEFAULT_JWT_PROVIDER + " could not be instantiated: " + ex, ex);
        }
    }

    /**
     * Creates a new instance of {@link JwtClaimsBuilder}
     * 
     * @return {@link JwtClaimsBuilder}
     */
    public abstract JwtClaimsBuilder claims();

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} from a map of claims.
     * 
     * @param claims the map with the claim name and value pairs. Claim value is converted to String unless it is
     *        an instance of {@code Boolean}, {@code Number}, {@code Collection}, {@code Map},
     *        {@code JsonObject} or {@code JsonArray}.
     * @return {@link JwtClaimsBuilder}
     */
    public abstract JwtClaimsBuilder claims(Map<String, Object> claims);

    /**
     * Creates a new instance of {@link JwtClaimsBuilder} from a JSON resource.
     * 
     * @param jsonLocation JSON resource location
     * @return {@link JwtClaimsBuilder}
     */
    public abstract JwtClaimsBuilder claims(String jsonLocation);

}
