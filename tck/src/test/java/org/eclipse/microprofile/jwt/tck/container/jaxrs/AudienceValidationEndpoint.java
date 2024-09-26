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
package org.eclipse.microprofile.jwt.tck.container.jaxrs;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.config.Names;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

/**
 * The common endpoint used by the various config tests
 */
@RequestScoped
@Path("/endp")
public class AudienceValidationEndpoint {
    private static Logger log = Logger.getLogger("AudienceValidationEndpoint");

    @Inject
    @ConfigProperty(name = Names.AUDIENCES)
    private Optional<String> audiences;
    @Inject
    @Claim(standard = Claims.aud)
    private ClaimValue<Optional<Set<String>>> aud;

    @PostConstruct
    private void init() {
        log.info(String.format("AudienceValidationEndpoint.init, aud: %s\n", aud));
    }

    /**
     * Check a token with an aud claim matches one of the mp.jwt.verify.audiences values
     *
     * @return result of validation test
     */
    @GET
    @Path("/verifyAudIsOk")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("Tester")
    public JsonObject verifyAudIsOk() {
        boolean pass = false;
        String msg;

        if (!aud.getValue().isPresent()) {
            // The aud claim should be provided for this endpoint
            msg = "MP-JWT missing aud claim, or injection of claim failed";
        } else if (audiences.isPresent()) {

            Set<String> claimAud = aud.getValue().get();
            String[] configAud = audiences.get().split(",");
            boolean match = false;
            for (String oneAud : claimAud) {
                for (int j = 0; j < configAud.length; j++) {
                    if (oneAud.equals(configAud[j])) {
                        match = true;
                    }
                }
            }
            if (match) {
                msg = String.format("endpoint accessed with audiences(%s) = config.audiences(%s) as expected PASS",
                        claimAud, Arrays.toString(configAud));
                pass = true;
            } else {
                msg = String.format("mp.jwt.verify.audiences(%s) != jwt.aud(%s)", Arrays.toString(configAud), claimAud);
            }
        } else {
            msg = "No mp.jwt.verify.audiences provided";
        }
        JsonObject result = Json.createObjectBuilder()
                .add("pass", pass)
                .add("msg", msg)
                .build();
        return result;
    }
}
