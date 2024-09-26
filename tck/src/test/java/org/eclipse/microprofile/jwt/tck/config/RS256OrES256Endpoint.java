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
package org.eclipse.microprofile.jwt.tck.config;

import java.io.StringReader;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;

import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

/**
 * The common endpoint used by the various config tests
 */
@RequestScoped
@Path("/endp")
public class RS256OrES256Endpoint {
    @Inject
    @Claim(standard = Claims.raw_token)
    private ClaimValue<String> rawToken;

    @GET
    @Path("/verifyToken")
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed("Tester")
    public String verifyRS256Token() {
        return getAlgorithm();
    }

    private String getAlgorithm() {
        JsonReader jsonReader = Json.createReader(new StringReader(rawToken.getValue().split(".")[0]));
        JsonObject headers = jsonReader.readObject();
        return headers.getString("alg");
    }
}
