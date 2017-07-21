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

import javax.security.auth.Subject;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A default implementation of JWTCallerPrincipal that wraps the Keycloak AccessToken.
 * @see MPAccessToken
 */
public class DefaultJWTCallerPrincipal extends JWTCallerPrincipal {
    private MPAccessToken jwt;

    public DefaultJWTCallerPrincipal(MPAccessToken jwt) {
        super(jwt.getOtherClaims().get("unique_username").toString());
        this.jwt = jwt;
    }

    @Override
    public String getIssuer() {
        return jwt.getIssuer();
    }

    @Override
    public String[] getAudience() {
        return jwt.getAudience();
    }

    @Override
    public String getSubject() {
        return jwt.getSubject();
    }

    @Override
    public String getUniqueUsername() {
        return getName();
    }

    @Override
    public String getTokenID() {
        return jwt.getId();
    }

    @Override
    public long getExpirationTime() {
        return jwt.getExpiration();
    }

    @Override
    public long getIssuedAtTime() {
        return jwt.getIssuedAt();
    }

    @Override
    public Set<String> getGroups() {
        HashSet<String> groups = new HashSet<>();
        // First look to the global level
        List<String> globalGroups = (List<String>) jwt.getOtherClaims().get("groups");
        if(globalGroups != null) {
            groups.addAll(globalGroups);
        }
        // Next look at each service in the resource access mapping
        Map<String, MPAccessToken.Access> serviceAccess = jwt.getResourceAccess();
        for(Map.Entry<String, MPAccessToken.Access> service : serviceAccess.entrySet()) {
            List<String> serviceGroups = (List<String>) service.getValue().getOtherClaims().get("groups");
            if(serviceGroups != null) {
                String serviceName = service.getKey();
                for (String group : serviceGroups) {
                    // Add each group with the service name prepended using the SERVICE_NAME_SEPARATOR
                    String serviceGroupName = serviceName + JWTCallerPrincipal.SERVICE_NAME_SEPARATOR + group;
                    groups.add(serviceGroupName);
                }
            }
        }
        return groups;
    }

    @Override
    public Set<String> getRoles() {
        HashSet<String> roles = new HashSet<>();
        // First look to the global level
        List<String> globalRoles = (List<String>) jwt.getOtherClaims().get("roles");
        if(globalRoles != null) {
            roles.addAll(globalRoles);
        }
        // Next look at each service in the resource access mapping
        Map<String, MPAccessToken.Access> serviceAccess = jwt.getResourceAccess();
        for(Map.Entry<String, MPAccessToken.Access> service : serviceAccess.entrySet()) {
            Set<String> serviceRoles = service.getValue().getRoles();
            if(serviceRoles != null) {
                String serviceName = service.getKey();
                for (String role : serviceRoles) {
                    // Add each role with the service name prepended using the SERVICE_NAME_SEPARATOR
                    String serviceRoleName = serviceName + JWTCallerPrincipal.SERVICE_NAME_SEPARATOR + role;
                    roles.add(serviceRoleName);
                }
            }
        }
        return roles;
    }

    @Override
    public boolean implies(Subject subject) {
        return false;
    }

    /**
     * TODO: showAll is ignored and currently assumed true
     * @param showAll - should all claims associated with the JWT be displayed or should only those defined in the
     *                JWTPrincipal interface be displayed.
     * @return JWTCallerPrincipal string view
     */
    @Override
    public String toString(boolean showAll) {
        String toString =  "DefaultJWTCallerPrincipal{" +
                "id='" + jwt.getId() + '\'' +
                ", name='" + jwt.getName() + '\'' +
                ", expiration=" + jwt.getExpiration() +
                ", notBefore=" + jwt.getNotBefore() +
                ", issuedAt=" + jwt.getIssuedAt() +
                ", issuer='" + jwt.getIssuer() + '\'' +
                ", audience=" + Arrays.toString(jwt.getAudience()) +
                ", subject='" + jwt.getSubject() + '\'' +
                ", type='" + jwt.getType() + '\'' +
                ", issuedFor='" + jwt.issuedFor + '\'' +
                ", otherClaims=" + jwt.getOtherClaims() +
                ", authTime=" + jwt.getAuthTime() +
                ", sessionState='" + jwt.getSessionState() + '\'' +
                ", givenName='" + jwt.getGivenName() + '\'' +
                ", familyName='" + jwt.getFamilyName() + '\'' +
                ", middleName='" + jwt.getMiddleName() + '\'' +
                ", nickName='" + jwt.getNickName() + '\'' +
                ", preferredUsername='" + jwt.getPreferredUsername() + '\'' +
                ", email='" + jwt.getEmail() + '\'' +
                ", trustedCertificates=" + jwt.getTrustedCertificates() +
                ", emailVerified=" + jwt.getEmailVerified() +
                ", allowedOrigins=" + jwt.getAllowedOrigins() +
                ", updatedAt=" + jwt.getUpdatedAt() +
                ", acr='" + jwt.getAcr() + '\''
                ;
        StringBuilder tmp = new StringBuilder(toString);
        tmp.append(", realmAccess={");
        if(jwt.getRealmAccess() != null) {
            tmp.append(", roles=");
            tmp.append(jwt.getRealmAccess().getRoles());
            tmp.append(", otherClaims=");
            tmp.append(jwt.getRealmAccess().getOtherClaims());
        }
        tmp.append("}, resourceAccess={");
        for(Map.Entry<String, MPAccessToken.Access> service : jwt.getResourceAccess().entrySet()) {
            tmp.append("{");
            tmp.append(service.getKey());
            tmp.append(", roles=");
            tmp.append(service.getValue().getRoles());
            tmp.append(", otherClaims=");
            tmp.append(service.getValue().getOtherClaims());
            tmp.append(",");
        }
        tmp.setLength(tmp.length()-1);
        tmp.append("}");
        return tmp.toString();
    }

}
