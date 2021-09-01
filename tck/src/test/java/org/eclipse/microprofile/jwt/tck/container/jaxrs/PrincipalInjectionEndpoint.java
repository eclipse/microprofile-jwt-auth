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
package org.eclipse.microprofile.jwt.tck.container.jaxrs;

import java.security.Principal;

import org.eclipse.microprofile.jwt.JsonWebToken;

import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;

/**
 * Validate that the injection of a {@linkplain Principal} works when using the MP-JWT feature. This validates that the
 * MP-JWT implementation is not interfering with the CDI built in Principal bean. This also validates that the
 * {@linkplain SecurityContext#getUserPrincipal()} is also an instance of the {@linkplain JsonWebToken} interface.
 */
@Path("/endp")
@RequestScoped
@RolesAllowed("Tester")
public class PrincipalInjectionEndpoint {
    @Inject
    private Principal principal;
    @Context
    private SecurityContext context;

    @GET
    @Path("/verifyInjectedPrincipal")
    @Produces(MediaType.APPLICATION_JSON)
    public JsonObject verifyInjectedPrincipal() {
        boolean pass = false;
        String msg;
        // Validate that the context principal is a JsonWebToken
        Principal jwtPrincipal = context.getUserPrincipal();
        if (jwtPrincipal == null) {
            msg = "SecurityContext#principal value is null, FAIL";
        } else if (jwtPrincipal instanceof JsonWebToken) {
            msg = "SecurityContext#getUserPrincipal is JsonWebToken, PASS";
            pass = true;
        } else {
            msg = String.format("principal: JsonWebToken != %s", jwtPrincipal.getClass().getCanonicalName());
        }
        // Validate that the injection built-in principal name matches the JsonWebToken name
        if (pass) {
            pass = false;
            if (principal == null) {
                msg = "Injected principal value is null, FAIL";
            } else if (!principal.getName().equals(jwtPrincipal.getName())) {
                msg = "Injected principal#name != jwtPrincipal#name, FAIL";
            } else {
                msg += "\nInjected Principal#getName matches, PASS";
                pass = true;
            }
        }

        JsonObject result = Json.createObjectBuilder()
                .add("pass", pass)
                .add("msg", msg)
                .build();
        return result;
    }

}
