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

import org.eclipse.microprofile.jwt.JWTCallerPrincipal;
import org.eclipse.microprofile.jwt.credential.JWTCredential;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.JsonWebToken;

import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import java.util.Set;

import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

/**
 * An IdentityStore implementation that validates JWT format supported by the Microprofile.
 */
public class DefaultJWTIdentityStore implements IdentityStore {
    private JWTAuthContextInfo authContextInfo;

    public DefaultJWTIdentityStore(JWTAuthContextInfo authContextInfo) {
        this.authContextInfo = authContextInfo;
    }

    @Override
    public CredentialValidationResult validate(Credential credential) {
        if(credential instanceof JWTCredential) {
            JWTCredential jwtCredential = JWTCredential.class.cast(credential);
            try {
                String token = jwtCredential.getToken();
                JWSInput input = new JWSInput(token);
                JsonWebToken jwt = input.readJsonContent(JsonWebToken.class);
                TokenVerifier verifier = TokenVerifier.create(token)
                        .publicKey(authContextInfo.getSignerKey())
                        .realmUrl(authContextInfo.getIssuedBy());
                verifier.getToken();

                JWTCallerPrincipal callerPrincipal = new JWTCallerPrincipal(jwt);
                Set<String> groups = callerPrincipal.getGroups();
                CredentialValidationResult result = new CredentialValidationResult(callerPrincipal, groups);
                return result;
            }
            catch (JWSInputException e) {
                e.printStackTrace();
            }
            catch (VerificationException e) {
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
