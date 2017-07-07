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

package org.eclipse.microprofile.jwt;

import org.keycloak.representations.JsonWebToken;

import javax.security.enterprise.CallerPrincipal;
import java.util.*;
import java.util.stream.Collectors;

/**
 * A standard CallerPrincipal implementation that provides access to the JWT claims that are required by
 * the microprofile token.
 */
public class JWTCallerPrincipal extends CallerPrincipal {
    /** TODO: need to decide on a JWT parsing/verification library or create one */
    private JsonWebToken jwt;
    private Set<String> groups;

    /**
     * Creates a caller principal with the parsed and validated JWT representation.
     * @param jwt - the validated JWT
     */
    public JWTCallerPrincipal(JsonWebToken jwt) {
        super(jwt.getSubject());
    }


    public String getJti() {
        return jwt.getId();
    }
    public String getIss() {
        return jwt.getIssuer();
    }
    public String[] getAud() {
        return jwt.getAudience();
    }
    public String getAzp() {
        return jwt.getIssuedFor();
    }
    public int getExp() {
        return jwt.getExpiration();
    }
    public int getIat() {
        return jwt.getIssuedAt();
    }
    public int getNbf() {
        return jwt.getNotBefore();
    }
    public String getPreferredUsername() {
        return (String) jwt.getOtherClaims().get("preferred_username");
    }
    public String getName() {
        return (String) jwt.getOtherClaims().get("unique_username");
    }
    public Set<String> getRoles() {
        List roleNames = (List) jwt.getOtherClaims().get("roles");
        Set<String> roles = Collections.emptySet();
        if(roleNames != null) {
            roleNames.stream().collect(Collectors.toSet());
        }
        return roles;
    }
    public boolean isCallerInRole(String role) {
        return false;
    }

    public Set<String> getGroups() {
        final Set<String> groups = new HashSet<>();
        if(jwt.getOtherClaims().get("groups") != null) {
            List groupNames = (List) jwt.getOtherClaims().get("groups");
            groupNames.stream().collect(Collectors.toSet());
        }
        else if(!getRoles().isEmpty()) {
            groups.addAll(getRoles());
        }
        else if(jwt.getOtherClaims().get("resource_access") != null) {
            Map<String, Object> resourceAccess = (Map<String, Object>) jwt.getOtherClaims().get("resource_access");
            for (String service : resourceAccess.keySet()) {
                Map serviceMap = (Map) resourceAccess.get(service);
                List roleNames = (List) serviceMap.get("roles");
                if(roleNames != null) {
                    roleNames.forEach(role -> groups.add(service + ":" + role));
                }
                List groupNames = (List) serviceMap.get("groups");
                if(groupNames != null) {
                    groupNames.forEach(group -> groups.add(service + ":" + group));
                }
            }
        }
        return groups;
    }
}
