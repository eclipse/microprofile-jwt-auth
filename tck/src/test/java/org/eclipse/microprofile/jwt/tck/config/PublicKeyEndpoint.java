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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Optional;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.config.Names;

/**
 * The endpoint used with the {@linkplain PublicKeyAsPEMTest}
 */
@RequestScoped
@Path("/endp")
public class PublicKeyEndpoint {

    @Inject
    @ConfigProperty(name = Names.VERIFIER_PUBLIC_KEY)
    private Optional<String> key;
    @Inject
    @ConfigProperty(name = Names.VERIFIER_PUBLIC_KEY_LOCATION)
    private Optional<String> location;
    @Inject
    @ConfigProperty(name = Names.ISSUER)
    private Optional<String> issuer;
    @Inject
    @Claim(standard = Claims.iss)
    private String iss;

    @GET
    @Path("/verifyKeyAsPEM")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("Tester")
    public JsonObject verifyKeyAsPEM() {
        boolean pass = false;
        String msg;
        // Check the injected iss claim against the config property
        String issValue = issuer.orElse("missing-issuer");
        if(issValue == null || issValue.length() == 0) {
            msg = Claims.iss.name()+" value is null or empty, FAIL";
        }
        else if(issValue.equals(iss)) {
            msg = Claims.iss.name()+" PASS";
            pass = true;
        }
        else {
            msg = String.format("%s: %s != %s", Claims.iss.name(), issValue, iss);
        }

        // Check the key exists and is a valid PEM public key
        try {
            PublicKey publicKey = SimpleTokenUtils.decodePublicKey(key.orElse("bad-key"));
            msg += " | key as PEM PASS";
            pass = true;
        }
        catch (Exception e) {
            msg = String.format("Failed to read key with exception: %s", e.getMessage());
        }

        JsonObject result = Json.createObjectBuilder()
            .add("pass", pass)
            .add("msg", msg)
            .build();
        return result;
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
            System.out.printf("verifyKeyLocationAsPEMResource, location=%s", locationValue);
            try {
                String pemValue = SimpleTokenUtils.readResource(locationValue);
                System.out.printf("verifyKeyLocationAsPEMResource, locationValue=%s", pemValue);
                PublicKey publicKey = SimpleTokenUtils.decodePublicKey(pemValue);
                System.out.printf("verifyKeyLocationAsPEMResource, publicKey=%s", publicKey);
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

    /**
     * Check the location exists and is a URL whose contents are valid PEM public key
     * @return result of validation test
     */
    @GET
    @Path("/verifyKeyLocationAsPEMUrl")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("Tester")
    public JsonObject verifyKeyLocationAsPEMUrl() {
        boolean pass = false;
        String msg;
        if(location.isPresent()) {
            String locationValue = location.get();
            System.out.printf("verifyKeyLocationAsPEMUrl, location=%s", locationValue);
            try {
                // Read the pem contents from the URL
                URL locationURL = new URL(locationValue);
                StringWriter pemContents = new StringWriter();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(locationURL.openStream()))) {
                    String line = reader.readLine();
                    while (line != null) {
                        pemContents.write(line);
                        pemContents.write('\n');
                        line = reader.readLine();
                    }
                }
                System.out.printf("verifyKeyLocationAsPEMUrl, locationValue=%s", pemContents.toString());
                // Decode the contents
                PublicKey publicKey = SimpleTokenUtils.decodePublicKey(pemContents.toString());
                System.out.printf("verifyKeyLocationAsPEMUrl, publicKey=%s", publicKey);
                msg = "key location as URL to PEM PASS";
                pass = true;
            }
            catch (MalformedURLException e) {
                msg = String.format("Failed to read location contents: %s", e.getMessage());
            }
            catch (IOException e) {
                msg = String.format("Failed to parse location as URL: %s", e.getMessage());
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

    /**
     * @return the /publicKey4k.pem classpath resource contents a PEM string
     */
    @GET
    @Path("/publicKey4k")
    @Produces(MediaType.TEXT_PLAIN)
    @PermitAll
    public String publicKey4k() throws IOException {
        return SimpleTokenUtils.readResource("/publicKey4k.pem");
    }
    /**
     * @return the /publicKey4k.pem classpath resource contents a JWKS object
     */
    @GET
    @Path("/publicKey4kAsJWKS")
    @Produces(MediaType.APPLICATION_JSON)
    @PermitAll
    public JsonObject publicKey4kAsJWKS() throws Exception {
        String pem = SimpleTokenUtils.readResource("/publicKey4k.pem");
        RSAPublicKey publicKey = (RSAPublicKey) SimpleTokenUtils.decodePublicKey(pem);
        JsonObjectBuilder jwksBuilder = Json.createObjectBuilder();
        JsonObjectBuilder keyBuilder = Json.createObjectBuilder();
        BigInteger nBI = publicKey.getModulus();
        byte[] nbytes = nBI.toByteArray();
        if ((nBI.bitLength() % 8 == 0) && nbytes[0] == 0 && nbytes.length > 1) {
            byte[] tmp = new byte[nbytes.length-1];
            System.arraycopy(nbytes, 1, tmp, 0, tmp.length);
            nbytes = tmp;
        }
        String n = new String(Base64.getUrlEncoder().withoutPadding().encode(nbytes));
        BigInteger eBI = publicKey.getPublicExponent();
        byte[] ebytes = eBI.toByteArray();
        if ((eBI.bitLength() % 8 == 0) && ebytes[0] == 0 && ebytes.length > 1) {
            byte[] tmp = new byte[nbytes.length-1];
            System.arraycopy(nbytes, 1, tmp, 0, tmp.length);
            ebytes = tmp;
        }
        String e = new String(Base64.getUrlEncoder().withoutPadding().encode(ebytes));

        keyBuilder
            .add("kty", "RSA")
            .add("use", "sig")
            .add("alg", "RS256")
            .add("kid", "pem-to-jwks")
            .add("e", e)
            .add("n", n);
        JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
        arrayBuilder.add(keyBuilder);
        jwksBuilder.add("keys", arrayBuilder);
        JsonObject jwks = jwksBuilder.build();
        return jwks;
    }
}
