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

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.idm.authorization.Permission;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A replacement of the org.keycloak.representations.AccessToken until the
 * https://issues.jboss.org/browse/KEYCLOAK-5207 feature request is supported.
 */
public class MPAccessToken extends IDToken {
    @JsonProperty("trusted-certs")
    protected Set<String> trustedCertificates;
    @JsonProperty("allowed-origins")
    protected Set<String> allowedOrigins;
    @JsonProperty("realm_access")
    protected MPAccessToken.Access realmAccess;
    @JsonProperty("resource_access")
    protected Map<String, Access> resourceAccess = new HashMap();
    @JsonProperty("authorization")
    protected MPAccessToken.Authorization authorization;

    public MPAccessToken() {
    }

    public Map<String, MPAccessToken.Access> getResourceAccess() {
        return this.resourceAccess;
    }

    public void setResourceAccess(Map<String, MPAccessToken.Access> resourceAccess) {
        this.resourceAccess = resourceAccess;
    }

    @JsonIgnore
    public boolean isVerifyCaller() {
        boolean isVerifyCaller = (this.getRealmAccess() != null && this.getRealmAccess().getVerifyCaller() != null)
                && this.getRealmAccess().getVerifyCaller();
        return isVerifyCaller;
    }

    @JsonIgnore
    public boolean isVerifyCaller(String resource) {
        MPAccessToken.Access access = this.getResourceAccess(resource);
        return access != null && access.getVerifyCaller() != null?access.getVerifyCaller().booleanValue():false;
    }

    @JsonIgnore
    public MPAccessToken.Access getResourceAccess(String resource) {
        return (MPAccessToken.Access)this.resourceAccess.get(resource);
    }

    public MPAccessToken.Access addAccess(String service) {
        MPAccessToken.Access access = (MPAccessToken.Access)this.resourceAccess.get(service);
        if(access != null) {
            return access;
        }
        else {
            access = new MPAccessToken.Access();
            this.resourceAccess.put(service, access);
            return access;
        }
    }

    public MPAccessToken id(String id) {
        return (MPAccessToken)super.id(id);
    }

    public MPAccessToken expiration(int expiration) {
        return (MPAccessToken)super.expiration(expiration);
    }

    public MPAccessToken notBefore(int notBefore) {
        return (MPAccessToken)super.notBefore(notBefore);
    }

    public MPAccessToken issuedAt(int issuedAt) {
        return (MPAccessToken)super.issuedAt(issuedAt);
    }

    public MPAccessToken issuer(String issuer) {
        return (MPAccessToken)super.issuer(issuer);
    }

    public MPAccessToken subject(String subject) {
        return (MPAccessToken)super.subject(subject);
    }

    public MPAccessToken type(String type) {
        return (MPAccessToken)super.type(type);
    }

    public Set<String> getAllowedOrigins() {
        return this.allowedOrigins;
    }

    public void setAllowedOrigins(Set<String> allowedOrigins) {
        this.allowedOrigins = allowedOrigins;
    }

    public MPAccessToken.Access getRealmAccess() {
        return this.realmAccess;
    }

    public void setRealmAccess(MPAccessToken.Access realmAccess) {
        this.realmAccess = realmAccess;
    }

    public Set<String> getTrustedCertificates() {
        return this.trustedCertificates;
    }

    public void setTrustedCertificates(Set<String> trustedCertificates) {
        this.trustedCertificates = trustedCertificates;
    }

    public MPAccessToken issuedFor(String issuedFor) {
        return (MPAccessToken)super.issuedFor(issuedFor);
    }

    public MPAccessToken.Authorization getAuthorization() {
        return this.authorization;
    }

    public void setAuthorization(MPAccessToken.Authorization authorization) {
        this.authorization = authorization;
    }

    public static class Authorization implements Serializable {
        @JsonProperty("permissions")
        private List<Permission> permissions;

        public Authorization() {
        }

        public List<Permission> getPermissions() {
            return this.permissions;
        }

        public void setPermissions(List<Permission> permissions) {
            this.permissions = permissions;
        }
    }

    public static class Access implements Serializable {
        @JsonProperty("roles")
        protected Set<String> roles;
        @JsonProperty("verify_caller")
        protected Boolean verifyCaller;
        protected Map<String, Object> otherClaims = new HashMap<>();

        public Access() {
        }

        public MPAccessToken.Access clone() {
            MPAccessToken.Access access = new MPAccessToken.Access();
            access.verifyCaller = this.verifyCaller;
            if(this.roles != null) {
                access.roles = new HashSet();
                access.roles.addAll(this.roles);
            }

            return access;
        }

        public Set<String> getRoles() {
            return this.roles;
        }

        public MPAccessToken.Access roles(Set<String> roles) {
            this.roles = roles;
            return this;
        }

        @JsonIgnore
        public boolean isUserInRole(String role) {
            return this.roles == null?false:this.roles.contains(role);
        }

        public MPAccessToken.Access addRole(String role) {
            if(this.roles == null) {
                this.roles = new HashSet();
            }

            this.roles.add(role);
            return this;
        }

        public Boolean getVerifyCaller() {
            return this.verifyCaller;
        }

        public MPAccessToken.Access verifyCaller(Boolean required) {
            this.verifyCaller = required;
            return this;
        }
        /**
         * This is a map of any other claims and data that might be in the Access.
         *
         * @return current other claims
         */
        @JsonAnyGetter
        public Map<String, Object> getOtherClaims() {
            return otherClaims;
        }

        @JsonAnySetter
        public void setOtherClaims(String name, Object value) {
            otherClaims.put(name, value);
        }
    }
}
