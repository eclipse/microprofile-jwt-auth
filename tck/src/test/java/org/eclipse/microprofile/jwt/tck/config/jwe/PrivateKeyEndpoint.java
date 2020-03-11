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
package org.eclipse.microprofile.jwt.tck.config.jwe;

import java.io.StringReader;
import java.security.PrivateKey;
import java.util.Optional;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.config.Names;
import org.eclipse.microprofile.jwt.tck.config.SimpleTokenUtils;

/**
 * The common endpoint used by the various private key config tests
 */
@RequestScoped
@Path("/endp")
public class PrivateKeyEndpoint {
    private static Logger log = Logger.getLogger("PrivateKeyEndpoint");

    @Inject
    @ConfigProperty(name = Names.DECRYPTOR_KEY_LOCATION)
    private Optional<String> location;
    
    @PostConstruct
    private void init() {
        log.info(String.format("PrivateKeyEndpoint.init, location: %s",  location.orElse("missing")));
    }

    @GET
    @Path("/verifyKeyLocationAsPEMResource")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("Tester")
    public JsonObject verifyKeyLocationAsPEMResource() {
        boolean pass = false;
        String msg;
        // Check the location exists and is a valid PEM public key
        if(location.isPresent()) {
            String locationValue = location.get();
            log.info(String.format("verifyKeyLocationAsPEMResource, location=%s", locationValue));
            try {
                String pemValue = SimpleTokenUtils.readResource(locationValue);
                log.info(String.format("verifyKeyLocationAsPEMResource, locationValue=%s", pemValue));
                PrivateKey privateKey = SimpleTokenUtils.decodePrivateKey(pemValue);
                log.info(String.format("verifyKeyLocationAsPEMResource, privateKey=%s", privateKey));
                msg = "key location as resource to PEM PASS";
                pass = true;
            }
            catch (Exception e) {
                msg = String.format("Failed to read key with exception: %s", e.getMessage());
            }
        }
        else {
            msg = "no location property injected";
        }

        JsonObject result = Json.createObjectBuilder()
            .add("pass", pass)
            .add("msg", msg)
            .build();
        return result;
    }

    @GET
    @Path("/verifyKeyLocationAsJWKResource")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("Tester")
    public JsonObject verifyKeyLocationAsJWKResource(@QueryParam("kid") String kid) {
        boolean pass = false;
        String msg;
        // Check the location exists and is a valid PEM public key
        if(location.isPresent()) {
            String locationValue = location.get();
            log.info(String.format("verifyKeyLocationAsJWKResource, location=%s", locationValue));
            try {
                String jwkValue = SimpleTokenUtils.readResource(locationValue);
                log.info(String.format("verifyKeyLocationAsJWKResource, locationValue=%s", jwkValue));
                StringBuilder msgBuilder = new StringBuilder();
                JsonObject jwk = Json.createReader(new StringReader(jwkValue)).readObject();
                if(verifyJWK(jwk, kid, msgBuilder)) {
                    PrivateKey privateKey = SimpleTokenUtils.decodeJWKSPrivateKey(jwkValue);
                    log.info(String.format("verifyKeyLocationAsJWKResource, privateKey=%s", privateKey));
                    msg = "key location as resource to JWK PASS";
                    pass = true;
                }
                else {
                    msg = msgBuilder.toString();
                }
            }
            catch (Exception e) {
                msg = String.format("Failed to read key with exception: %s", e.getMessage());
            }
        }
        else {
            msg = "no location property injected";
        }

        JsonObject result = Json.createObjectBuilder()
            .add("pass", pass)
            .add("msg", msg)
            .build();
        return result;
    }

    @GET
    @Path("/verifyKeyLocationAsJWKSResource")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("Tester")
    public JsonObject verifyKeyLocationAsJWKSResource(@QueryParam("kid") String kid) {
        boolean pass = false;
        String msg;
        // Check the location exists and is a valid PEM public key
        if(location.isPresent()) {
            String locationValue = location.get();
            log.info(String.format("verifyKeyLocationAsJWKSResource, location=%s", locationValue));
            try {
                String jwkValue = SimpleTokenUtils.readResource(locationValue);
                log.info(String.format("verifyKeyLocationAsJWKResource, locationValue=%s", jwkValue));
                StringBuilder msgBuilder = new StringBuilder();
                JsonObject jwk = Json.createReader(new StringReader(jwkValue)).readObject().getJsonArray("keys").getJsonObject(0);
                if(verifyJWK(jwk, kid, msgBuilder)) {
                    PrivateKey privateKey = SimpleTokenUtils.decodeJWKSPrivateKey(jwkValue);
                    log.info(String.format("verifyKeyLocationAsJWKResource, privateKey=%s", privateKey));
                    msg = "key location as resource to JWKS PASS";
                    pass = true;
                }
                else {
                    msg = msgBuilder.toString();
                }
            }
            catch (Exception e) {
                msg = String.format("Failed to read key with exception: %s", e.getMessage());
            }
        }
        else {
            msg = "no location property injected";
        }

        JsonObject result = Json.createObjectBuilder()
            .add("pass", pass)
            .add("msg", msg)
            .build();
        return result;
    }

    private boolean verifyJWK(JsonObject key, String kid, StringBuilder msg) {

        boolean pass = true;
        if(!key.getJsonString("kty").getString().equals("RSA")) {
            msg.append("key != RSA");
            pass = false;
        }
        if(!key.getJsonString("use").getString().equals("enc")) {
            msg.append("use != enc");
            pass = false;
        }
        if(!key.getJsonString("kid").getString().equals(kid)) {
            log.info(String.format("kid != %s, was: %s", kid, key.getJsonString("kid").getString()));
            msg.append(String.format("kid != %s, was: %s", kid, key.getJsonString("kid").getString()));
            pass = false;
        }
        if(!key.getJsonString("alg").getString().equals("RSA-OAEP")) {
            msg.append("alg != RSA-OAEP");
            pass = false;
        }
        if(!key.getJsonString("e").getString().equals("AQAB")) {
            msg.append("e != AQAB");
            pass = false;
        }
        if(!key.getJsonString("n").getString().startsWith("vNrRiMGbg3g4d6oApaDCQ09LeCL8Y2ig336NzPlAtzsPscp7y")) {
            msg.append("n != vNrRiMGbg3g4d6oApaDCQ09LeCL8Y2ig336NzPlAtzsPscp7y...");
            pass = false;
        }
        if(!key.getJsonString("d").getString().startsWith("RQ_IHDigxB0MmUYD4o29PJwcvxwcK8YxPkmrVU-5CMiCXsPrL")) {
            msg.append("n != RQ_IHDigxB0MmUYD4o29PJwcvxwcK8YxPkmrVU-5CMiCXsPrL...");
            pass = false;
        }
        if(pass) {
            msg.append("key as JWKS PASS");
        }
        return pass;
    }
}
