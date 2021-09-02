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
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Optional;
import java.util.logging.Logger;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.config.Names;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

/**
 * The common endpoint used by the various config tests
 */
@RequestScoped
@Path("/endp")
public class PublicKeyEndpoint {
    private static Logger log = Logger.getLogger("PublicKeyEndpoint");

    @Inject
    @ConfigProperty(name = Names.VERIFIER_PUBLIC_KEY)
    private Optional<String> key;

    @Inject
    @ConfigProperty(name = Names.VERIFIER_PUBLIC_KEY_LOCATION)
    private Optional<String> location;

    @Inject
    @ConfigProperty(name = Names.VERIFIER_PUBLIC_KEY_ALGORITHM, defaultValue = "RS256")
    private String algorithm;

    @Inject
    @ConfigProperty(name = Names.ISSUER)
    private Optional<String> issuer;

    @Inject
    @Claim(standard = Claims.iss)
    private ClaimValue<Optional<String>> iss;

    @PostConstruct
    private void init() {
        log.info(String.format("PublicKeyEndpoint.init, key: %s, location: %s, issuer: %s\n",
                key.orElse("Missing"), location.orElse("missing"),
                issuer.orElse("missing")));
    }

    /**
     * Verify that the injected key is a PEM RSA public key
     * 
     * @return json object for test result
     */
    @GET
    @Path("/verifyKeyAsPEM")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("Tester")
    public JsonObject verifyKeyAsPEM() {
        boolean pass = false;
        String msg;
        // Check the injected iss claim against the config property
        String issValue = issuer.orElse("missing-issuer");
        if (issValue == null || issValue.length() == 0) {
            msg = Claims.iss.name() + " value is null or empty, FAIL";
        } else if (issValue.equals(iss)) {
            msg = Claims.iss.name() + " PASS";
            pass = true;
        } else {
            msg = String.format("%s: %s != %s", Claims.iss.name(), issValue, iss);
        }

        // Check the key exists and is a valid PEM public key
        try {
            if ("RS256".equals(algorithm)) {
                PublicKey publicKey = SimpleTokenUtils.decodePublicKey(key.orElse("bad-key"));
                if (publicKey instanceof RSAPublicKey) {
                    msg += " | key as PEM PASS";
                    pass = true;
                } else {
                    pass = false;
                }
            } else if ("ES256".equals(algorithm)) {
                PublicKey publicKey = SimpleTokenUtils.decodeECPublicKey(key.orElse("bad-key"));
                if (publicKey instanceof ECPublicKey) {
                    msg += " | key as PEM PASS";
                    pass = true;
                } else {
                    pass = false;
                }
            } else {
                pass = false;
            }
        } catch (Exception e) {
            msg = String.format("Failed to read key with exception: %s", e.getMessage());
            pass = false;
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
        String msg = null;
        // Check the location exists and is a valid PEM public key
        if (location.isPresent()) {
            String locationValue = location.get();
            log.info(String.format("verifyKeyLocationAsPEMResource, location=%s", locationValue));
            try {
                String pemValue = SimpleTokenUtils.readResource(locationValue);
                log.info(String.format("verifyKeyLocationAsPEMResource, locationValue=%s", pemValue));
                if ("RS256".equals(algorithm)) {
                    PublicKey publicKey = SimpleTokenUtils.decodePublicKey(pemValue);
                    if (publicKey instanceof RSAPublicKey) {
                        log.info(String.format("verifyKeyLocationAsPEMResource, publicKey=%s", publicKey));
                        msg = "key location as resource to PEM PASS";
                        pass = true;
                    } else {
                        pass = false;
                    }
                } else if ("ES256".equals(algorithm)) {
                    PublicKey publicKey = SimpleTokenUtils.decodeECPublicKey(pemValue);
                    if (publicKey instanceof ECPublicKey) {
                        log.info(String.format("verifyKeyLocationAsPEMResource, publicKey=%s", publicKey));
                        msg = "key location as resource to PEM PASS";
                        pass = true;
                    } else {
                        pass = false;
                    }
                } else {
                    pass = false;
                }
            } catch (Exception e) {
                msg = String.format("Failed to read key with exception: %s", e.getMessage());
            }
        } else {
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
     * 
     * @return result of validation test
     */
    @GET
    @Path("/verifyKeyLocationAsPEMUrl")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("Tester")
    public JsonObject verifyKeyLocationAsPEMUrl() {
        boolean pass = false;
        String msg;
        if (location.isPresent()) {
            String locationValue = location.get();
            log.info(String.format("verifyKeyLocationAsPEMUrl, location=%s", locationValue));
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
                log.info(String.format("verifyKeyLocationAsPEMUrl, locationValue=%s", pemContents.toString()));
                // Decode the contents
                PublicKey publicKey = SimpleTokenUtils.decodePublicKey(pemContents.toString());
                log.info(String.format("verifyKeyLocationAsPEMUrl, publicKey=%s", publicKey));
                msg = "key location as URL to PEM PASS";
                pass = true;
            } catch (MalformedURLException e) {
                msg = String.format("Failed to read location contents: %s", e.getMessage());
            } catch (IOException e) {
                msg = String.format("Failed to parse location as URL: %s", e.getMessage());
            } catch (Exception e) {
                msg = String.format("Failed to read key with exception: %s", e.getMessage());
            }
        } else {
            msg = "no location property injected";
        }

        JsonObject result = Json.createObjectBuilder()
                .add("pass", pass)
                .add("msg", msg)
                .build();
        return result;
    }

    /**
     * Verify that the injected key is a JWK public key
     * 
     * @return json object for test result
     */
    @GET
    @Path("/verifyKeyAsJWK")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("Tester")
    public JsonObject verifyKeyAsJWK(@QueryParam("kid") String kid) {
        boolean pass = false;
        String msg;

        // Check that the key exists and is a valid JWKS public key
        try {
            String jsonJwk = key.get();
            StringBuilder msgBuilder = new StringBuilder();
            JsonObject jwk = Json.createReader(new StringReader(jsonJwk)).readObject();
            pass = verifyJWK(jwk, kid, msgBuilder);
            msg = msgBuilder.toString();
        } catch (Exception e) {
            msg = String.format("Failed to read key with exception: %s", e.getMessage());
        }

        JsonObject result = Json.createObjectBuilder()
                .add("pass", pass)
                .add("msg", msg)
                .build();
        return result;
    }

    /**
     * Verify that the injected key is a base64 encoded JWK public key
     * 
     * @return json object for test result
     */
    @GET
    @Path("/verifyKeyAsBase64JWK")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("Tester")
    public JsonObject verifyKeyAsBase64JWK(@QueryParam("kid") String kid) {
        boolean pass = false;
        String msg;

        // Check that the key exists and is a valid base64 JWK public key
        try {
            String base64Jwk = key.get();
            log.info("verifyKeyAsBase64JWK, base64Jwk=" + base64Jwk);
            byte[] data = Base64.getDecoder().decode(base64Jwk);
            String jsonJwk = new String(data);
            log.info("verifyKeyAsBase64JWK, jsonJwk=" + jsonJwk);
            StringBuilder msgBuilder = new StringBuilder();
            JsonObject jwk = Json.createReader(new StringReader(jsonJwk)).readObject();
            pass = verifyJWK(jwk, kid, msgBuilder);
            msg = msgBuilder.toString();
        } catch (Exception e) {
            msg = String.format("Failed to read key with exception: %s", e.getMessage());
        }

        JsonObject result = Json.createObjectBuilder()
                .add("pass", pass)
                .add("msg", msg)
                .build();
        return result;
    }

    /**
     * Verify that the injected key is a JWKS public key
     * 
     * @return json object for test result
     */
    @GET
    @Path("/verifyKeyAsJWKS")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("Tester")
    public JsonObject verifyKeyAsJWKS(@QueryParam("kid") String kid) {
        boolean pass = false;
        String msg;

        // Check that the key exists and is a valid JWKS public key
        try {
            String jsonJwk = key.get();
            StringBuilder msgBuilder = new StringBuilder();
            pass = verifyJWKS(jsonJwk, kid, msgBuilder);
            msg = msgBuilder.toString();
        } catch (Exception e) {
            msg = String.format("Failed to read key with exception: %s", e.getMessage());
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
        if (location.isPresent()) {
            String locationValue = location.get();
            log.info(String.format("verifyKeyLocationAsJWKResource, location=%s", locationValue));
            try {
                String jwkValue = SimpleTokenUtils.readResource(locationValue);
                log.info(String.format("verifyKeyLocationAsJWKResource, locationValue=%s", jwkValue));
                StringBuilder msgBuilder = new StringBuilder();
                JsonObject jwk = Json.createReader(new StringReader(jwkValue)).readObject();
                if (verifyJWK(jwk, kid, msgBuilder)) {
                    if ("RS256".equals(algorithm)) {
                        PublicKey publicKey = SimpleTokenUtils.decodeJWKSPublicKey(jwkValue);
                        log.info(String.format("verifyKeyLocationAsJWKResource, publicKey=%s", publicKey));
                    }
                    msg = "key location as resource to JWK PASS";
                    pass = true;
                } else {
                    msg = msgBuilder.toString();
                }
            } catch (Exception e) {
                msg = String.format("Failed to read key with exception: %s", e.getMessage());
            }
        } else {
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
        if (location.isPresent()) {
            String locationValue = location.get();
            log.info(String.format("verifyKeyLocationAsJWKSResource, location=%s", locationValue));
            try {
                String jwksValue = SimpleTokenUtils.readResource(locationValue);
                log.info(String.format("verifyKeyLocationAsJWKSResource, locationValue=%s", jwksValue));
                StringBuilder msgBuilder = new StringBuilder();
                if (verifyJWKS(jwksValue, kid, msgBuilder)) {
                    PublicKey publicKey = SimpleTokenUtils.decodeJWKSPublicKey(jwksValue);
                    log.info(String.format("verifyKeyLocationAsJWKSResource, publicKey=%s", publicKey));
                    msg = "key location as resource to JWKS PASS";
                    pass = true;
                } else {
                    msg = msgBuilder.toString();
                }
            } catch (Exception e) {
                msg = String.format("Failed to read key with exception: %s", e.getMessage());
            }
        } else {
            msg = "no location property injected";
        }

        JsonObject result = Json.createObjectBuilder()
                .add("pass", pass)
                .add("msg", msg)
                .build();
        return result;
    }

    /**
     * Check the location exists and is a URL whose contents are valid JWKS public key
     * 
     * @param kid
     *            - expected kid of JWKS
     * @return result of validation test
     */
    @GET
    @Path("/verifyKeyLocationAsJWKSUrl")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("Tester")
    public JsonObject verifyKeyLocationAsJWKSUrl(@QueryParam("kid") String kid) {
        boolean pass = false;
        String msg;
        if (location.isPresent()) {
            String locationValue = location.get();
            log.info(String.format("verifyKeyLocationAsJWKSUrl, location=%s", locationValue));
            try {
                // Read the pem contents from the URL
                URL locationURL = new URL(locationValue);
                StringWriter jwksContents = new StringWriter();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(locationURL.openStream()))) {
                    String line = reader.readLine();
                    while (line != null) {
                        jwksContents.write(line);
                        jwksContents.write('\n');
                        line = reader.readLine();
                    }
                }
                log.info(String.format("verifyKeyLocationAsJWKSUrl, locationValue=%s", jwksContents.toString()));
                StringBuilder msgBuilder = new StringBuilder();
                if (verifyJWKS(jwksContents.toString(), kid, msgBuilder)) {
                    if ("RS256".equals(algorithm)) {
                        PublicKey publicKey = SimpleTokenUtils.decodeJWKSPublicKey(jwksContents.toString());
                        log.info(String.format("verifyKeyLocationAsJWKSResource, publicKey=%s", publicKey));
                    }
                    msg = "key location as URL to JWKS PASS";
                    pass = true;
                } else {
                    msg = msgBuilder.toString();
                }
            } catch (MalformedURLException e) {
                msg = String.format("Failed to read location contents: %s", e.getMessage());
            } catch (IOException e) {
                msg = String.format("Failed to parse location as URL: %s", e.getMessage());
            } catch (Exception e) {
                msg = String.format("Failed to read key with exception: %s", e.getMessage());
            }
        } else {
            msg = "no location property injected";
        }

        JsonObject result = Json.createObjectBuilder()
                .add("pass", pass)
                .add("msg", msg)
                .build();
        return result;
    }
    /**
     * Check a token with an iss matches the mp.jwt.verify.issuer value
     * 
     * @return result of validation test
     */
    @GET
    @Path("/verifyIssIsOk")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed("Tester")
    public JsonObject verifyIssIsOk() {
        boolean pass = false;
        String msg;

        if (!iss.getValue().isPresent()) {
            // The iss claim should be provided for this endpoint
            msg = String.format("MP-JWT missing iss claim");
        } else if (issuer.isPresent()) {
            String claimIss = iss.getValue().get();
            String configIss = issuer.get();
            if (configIss.equals(claimIss)) {
                msg = String.format("endpoint accessed with iss(%s) = config.iss(%s) as expected PASS",
                        claimIss, configIss);
                pass = true;
            } else {
                msg = String.format("mp.jwt.verify.issuer(%s) != jwt.iss(%s)", configIss, claimIss);
            }
        } else {
            msg = "No mp.jwt.verify.issuer provided";
        }
        JsonObject result = Json.createObjectBuilder()
                .add("pass", pass)
                .add("msg", msg)
                .build();
        return result;
    }

    /**
     * An endpoint that returns the contents of the bundled /publicKey4k.pem key
     * 
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
     * An endpoint that converts the bundled /publicKey4k.pem key in the corresponding JWKS format
     * 
     * @param kid
     *            - the kid to use in the JWKS
     * @return the /publicKey4k.pem classpath resource contents a JWKS object
     */
    @GET
    @Path("/publicKey4kAsJWKS")
    @Produces(MediaType.APPLICATION_JSON)
    @PermitAll
    public JsonObject publicKey4kAsJWKS(@QueryParam("kid") String kid) throws Exception {
        String pem = SimpleTokenUtils.readResource("/publicKey4k.pem");
        RSAPublicKey publicKey = (RSAPublicKey) SimpleTokenUtils.decodePublicKey(pem);
        JsonObjectBuilder jwksBuilder = Json.createObjectBuilder();
        JsonObjectBuilder keyBuilder = Json.createObjectBuilder();
        BigInteger nBI = publicKey.getModulus();
        byte[] nbytes = nBI.toByteArray();
        if ((nBI.bitLength() % 8 == 0) && nbytes[0] == 0 && nbytes.length > 1) {
            byte[] tmp = new byte[nbytes.length - 1];
            System.arraycopy(nbytes, 1, tmp, 0, tmp.length);
            nbytes = tmp;
        }
        String n = new String(Base64.getUrlEncoder().withoutPadding().encode(nbytes));
        BigInteger eBI = publicKey.getPublicExponent();
        byte[] ebytes = eBI.toByteArray();
        if ((eBI.bitLength() % 8 == 0) && ebytes[0] == 0 && ebytes.length > 1) {
            byte[] tmp = new byte[nbytes.length - 1];
            System.arraycopy(nbytes, 1, tmp, 0, tmp.length);
            ebytes = tmp;
        }
        String e = new String(Base64.getUrlEncoder().withoutPadding().encode(ebytes));

        keyBuilder
                .add("kty", "RSA")
                .add("use", "sig")
                .add("alg", "RS256")
                .add("kid", kid)
                .add("e", e)
                .add("n", n);
        JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
        arrayBuilder.add(keyBuilder);
        jwksBuilder.add("keys", arrayBuilder);
        JsonObject jwks = jwksBuilder.build();
        return jwks;
    }

    /**
     * Verify a JWKS object string against the expected values used by the tck
     * 
     * @param jwksJson
     *            - JSON string for JWKS
     * @param kid
     *            - the kid parameter to verify
     * @param msg
     *            - builder to return failure messages in
     * @return true if verified, false otherwise
     */
    private boolean verifyJWKS(String jwksJson, String kid, StringBuilder msg) {
        boolean pass;
        JsonObject jwks = Json.createReader(new StringReader(jwksJson)).readObject();
        JsonArray keys = jwks.getJsonArray("keys");
        if (keys != null) {
            JsonObject key = keys.getJsonObject(0);
            StringBuilder msgBuilder = new StringBuilder();
            pass = verifyJWK(key, kid, msgBuilder);
        } else {
            msg.append("No keys member found in: " + jwks);
            pass = false;
        }
        return pass;
    }
    private boolean verifyJWK(JsonObject key, String kid, StringBuilder msg) {

        boolean pass = true;

        String expectedKty = "RS256".equals(algorithm) ? "RSA" : "EC";
        if (!key.getJsonString("kty").getString().equals(expectedKty)) {
            msg.append("key != " + expectedKty);
            pass = false;
        }
        if (!key.getJsonString("use").getString().equals("sig")) {
            msg.append("use != sig");
            pass = false;
        }
        if (!key.getJsonString("kid").getString().equals(kid)) {
            log.info(String.format("kid != %s, was: %s", kid, key.getJsonString("kid").getString()));
            msg.append(String.format("kid != %s, was: %s", kid, key.getJsonString("kid").getString()));
            pass = false;
        }
        if (!key.getJsonString("alg").getString().equals(algorithm)) {
            msg.append("alg != " + algorithm);
            pass = false;
        }
        if ("RS256".equals(algorithm)) {
            if (!key.getJsonString("e").getString().equals("AQAB")) {
                msg.append("e != AQAB");
                pass = false;
            }
            if (!key.getJsonString("n").getString().startsWith("tL6HShqY5H4y56rsCo7VdhT9")) {
                msg.append("n != tL6HShqY5H4y56rsCo7VdhT9...");
                pass = false;
            }
        } else if ("ES256".equals(algorithm)) {
            if (!key.getJsonString("crv").getString().equals("P-256")) {
                msg.append("crv != P-256");
                pass = false;
            }
            if (!key.getJsonString("x").getString().startsWith("w4HohvwOj21FBQE1Pr")) {
                msg.append("x != w4HohvwOj21FBQE1Pr...");
                pass = false;
            }
            if (!key.getJsonString("y").getString().startsWith("osZEjUhZa79-kClcGm")) {
                msg.append("y != osZEjUhZa79-kClcGm...");
                pass = false;
            }
        } else {
            pass = false;
        }
        if (pass) {
            msg.append("key as JWKS PASS");
        }
        return pass;
    }
}
