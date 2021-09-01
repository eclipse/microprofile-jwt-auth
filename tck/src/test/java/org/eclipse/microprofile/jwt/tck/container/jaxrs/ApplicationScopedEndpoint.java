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
package org.eclipse.microprofile.jwt.tck.container.jaxrs;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.inject.Provider;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

@Path("/endp")
@RolesAllowed({"Echoer", "Tester"})
@ApplicationScoped
public class ApplicationScopedEndpoint {

    @Inject
    private JsonWebToken jwt;

    @Inject
    @Claim("raw_token")
    private ClaimValue<String> rawToken;

    @Inject
    @Claim("raw_token")
    private Provider<String> providedRawToken;

    @GET
    @Path("/verifyInjectedRawTokenClaimValue")
    @Produces(MediaType.APPLICATION_JSON)
    public JsonObject verifyInjectedRawTokenClaimValue(@QueryParam("raw_token") String rt) {
        return verifyRawToken(rawToken.getValue(), rt);
    }

    @GET
    @Path("/verifyInjectedRawTokenJwt")
    @Produces(MediaType.APPLICATION_JSON)
    public JsonObject verifyInjectedRawTokenJwt(@QueryParam("raw_token") String rt) {
        return verifyRawToken(jwt.getRawToken(), rt);
    }

    @GET
    @Path("/verifyInjectedRawTokenProvider")
    @Produces(MediaType.APPLICATION_JSON)
    public JsonObject verifyInjectedRawTokenProvider(@QueryParam("raw_token") String rt) {
        return verifyRawToken(providedRawToken.get(), rt);
    }

    private static JsonObject verifyRawToken(String injectedRawToken, String rawTokenQueryParam) {
        boolean pass = false;
        String msg;
        if (injectedRawToken == null || injectedRawToken.length() == 0) {
            msg = Claims.raw_token.name() + "value is null or empty, FAIL";
        } else if (injectedRawToken.equals(rawTokenQueryParam)) {
            msg = Claims.raw_token.name() + " PASS";
            pass = true;
        } else {
            msg = String.format("%s: %s != %s", Claims.raw_token.name(), injectedRawToken, rawTokenQueryParam);
        }
        JsonObject result = Json.createObjectBuilder()
                .add("pass", pass)
                .add("msg", msg)
                .add("injectedRawToken", injectedRawToken)
                .build();
        return result;
    }
}
