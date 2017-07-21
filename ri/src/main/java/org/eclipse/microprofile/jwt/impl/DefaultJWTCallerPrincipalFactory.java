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
package org.eclipse.microprofile.jwt.impl;

import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.principal.ParseException;
import org.eclipse.microprofile.jwt.identitystore.JWTAuthContextInfo;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;

import javax.enterprise.inject.spi.CDI;

/**
 * A default implementation of the abstract JWTCallerPrincipalFactory that uses the Keycloak token parsing classes.
 */
public class DefaultJWTCallerPrincipalFactory extends JWTCallerPrincipalFactory {
    private static JWTAuthContextInfo authContextInfo;

    /**
     * Tries to load the JWTAuthContextInfo from CDI if the class level authContextInfo has not been set.
     */
    public DefaultJWTCallerPrincipalFactory() {
        // Find a provider for the JWTAuthContextInfo
        CDI<Object> cdi = CDI.current();
        JWTAuthContextInfo aci = cdi.select(JWTAuthContextInfo.class).get();
        if(authContextInfo == null && aci != null) {
            authContextInfo = aci;
        }
    }

    /**
     * Allow one to override the JWTAuthContextInfo for environments without CDI or that don't want to.
     * @return the current class level JWTAuthContextInfo
     */
    public static JWTAuthContextInfo getAuthContextInfo() {
        return authContextInfo;
    }

    /**
     * Allow one to override the JWTAuthContextInfo for environments without CDI or that don't want to.
     * @param authContextInfo - the current class level JWTAuthContextInfo
     */
    public static void setAuthContextInfo(JWTAuthContextInfo authContextInfo) {
        DefaultJWTCallerPrincipalFactory.authContextInfo = authContextInfo;
    }

    @Override
    public JWTCallerPrincipal parse(String token) throws ParseException {
        JWTCallerPrincipal principal = null;
        try {

            // Verify the token
            TokenVerifier<MPAccessToken> verifier = TokenVerifier.create(token, MPAccessToken.class)
                    .publicKey(authContextInfo.getSignerKey())
                    .realmUrl(authContextInfo.getIssuedBy());
            MPAccessToken jwt = verifier.getToken();
            principal = new DefaultJWTCallerPrincipal(jwt);
        }
        catch (VerificationException e) {
            throw new ParseException("Failed to verify the input token", e);
        }
        return principal;
    }
}
