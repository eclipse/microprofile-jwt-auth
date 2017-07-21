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
package org.eclipse.microprofile.jwt.identitystore;

import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.principal.ParseException;
import org.eclipse.microprofile.jwt.credential.JWTCredential;

import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import java.util.Set;

import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

/**
 * An IdentityStore implementation that validates JWT format supported by the Microprofile.
 */
public class DefaultJWTIdentityStore implements IdentityStore {

    @Override
    public CredentialValidationResult validate(Credential credential) {
        if(credential instanceof JWTCredential) {
            JWTCredential jwtCredential = JWTCredential.class.cast(credential);
            try {
                String token = jwtCredential.getToken();

                JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
                JWTCallerPrincipal callerPrincipal = factory.parse(token);
                Set<String> groups = callerPrincipal.getGroups();
                CredentialValidationResult result = new CredentialValidationResult(callerPrincipal, groups);
                return result;
            }
            catch (ParseException e) {
                e.printStackTrace();
            }
        }
        return NOT_VALIDATED_RESULT;
    }

    @Override
    public Set<String> getCallerGroups(CredentialValidationResult validationResult) {
        return validationResult.getCallerGroups();
    }
}
