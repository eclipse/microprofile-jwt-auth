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

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.TCKConstants;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_CDI;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_JAXRS;

/**
 * Tests of the MP-JWT auth method as expected by the MP-JWT RBAC 1.0 spec
 */
public class RolesAllowedTest extends Arquillian {

    /**
     * The test generated JWT token string
     */
    private static String token;
    // Time claims in the token
    private static Long iatClaim;
    private static Long authTimeClaim;
    private static Long expClaim;

    /**
     * The base URL for the container under test
     */
    @ArquillianResource
    private URL baseURL;

    /**
     * Create a CDI aware base web application archive
     * @return the base base web application archive
     * @throws IOException - on resource failure
     */
    @Deployment(testable=true)
    public static WebArchive createDeployment() throws IOException {
        URL publicKey = RolesAllowedTest.class.getResource("/publicKey.pem");
        WebArchive webArchive = ShrinkWrap
            .create(WebArchive.class, "RolesAllowedTest.war")
            .addAsResource(publicKey, "/publicKey.pem")
            .addClass(RolesEndpoint.class)
            .addClass(TCKApplication.class)
            .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml")
            .addAsWebInfResource("WEB-INF/web.xml", "web.xml")
            ;
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @BeforeClass(alwaysRun=true)
    public static void generateToken() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        token = TokenUtils.generateTokenString("/RolesEndpoint.json", null, timeClaims);
        iatClaim = timeClaims.get(Claims.iat.name());
        authTimeClaim = timeClaims.get(Claims.auth_time.name());
        expClaim = timeClaims.get(Claims.exp.name());
    }

    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with no token fails with 403")
    public void callEchoNoAuth() throws Exception {
        String uri = baseURL.toExternalForm() + "/endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello")
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_UNAUTHORIZED);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with expired token fails with 403")
    public void callEchoExpiredToken() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.EXP);
        String token = TokenUtils.generateTokenString("/RolesEndpoint.json", invalidFields);
        System.out.printf("jwt: %s\n", token);

        String uri = baseURL.toExternalForm() + "/endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello")
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_UNAUTHORIZED);
        String reply = response.readEntity(String.class);
    }

    /**
     * Used to test how a standard auth-method works with the authorization layer.
     * @throws Exception
     */
    @RunAsClient
    @Test(groups = TCKConstants.TEST_GROUP_DEBUG, description = "Internal debugging test to test BASIC auth behavior")
    public void callEchoBASIC() throws Exception {
        byte[] tokenb = Base64.getEncoder().encode("jdoe@example.com:password".getBytes());
        String token = new String(tokenb);
        System.out.printf("basic: %s\n", token);

        String uri = baseURL.toExternalForm() + "/endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello")
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "BASIC "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        String reply = response.readEntity(String.class);
        Assert.assertEquals(reply, "hello, user=jdoe@example.com");
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with MP-JWT succeeds")
    public void callEcho() throws Exception {
        System.out.printf("jwt: %s\n", token);

        String uri = baseURL.toExternalForm() + "/endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello")
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        String reply = response.readEntity(String.class);
        Assert.assertEquals(reply, "hello, user=jdoe@example.com");
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with MP-JWT but no associated role fails with 403")
    public void callEcho2() throws Exception {
        System.out.printf("jwt: %s\n", token);

        String uri = baseURL.toExternalForm() + "/endp/echo2";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello")
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        String reply = response.readEntity(String.class);
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_FORBIDDEN);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS,
        description = "Validate a request with MP-JWT SecurityContext.getUserPrincipal() is a JsonWebToken")
    public void getPrincipalClass() throws Exception {
        String uri = baseURL.toExternalForm() + "/endp/getPrincipalClass";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        String[] ifaces = reply.split(",");
        boolean hasJsonWebToken = false;
        for(String iface : ifaces) {
            hasJsonWebToken |= iface.equals(JsonWebToken.class.getTypeName());
        }
        Assert.assertTrue(hasJsonWebToken, "PrincipalClass has JsonWebToken interface");
    }

    /**
     * This test requires that the server provide a mapping from the group1 grant in the token to a Group1MappedRole
     * application declared role.
     */
    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS,
        description = "Validate a request without an MP-JWT to endpoint requiring role mapping has HTTP_OK")
    public void testNeedsGroup1Mapping() {
        String uri = baseURL.toExternalForm() + "/endp/needsGroup1Mapping";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        System.out.println(reply);
    }

    @Test(groups = TEST_GROUP_CDI,
        description = "")
    public void getInjectedPrincipal() throws Exception {
        String uri = baseURL.toExternalForm() + "/endp/getInjectedPrincipal";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        String reply = response.readEntity(String.class);
        String[] ifaces = reply.split(",");
        boolean hasJsonWebToken = false;
        for(String iface : ifaces) {
            hasJsonWebToken |= iface.equals(JsonWebToken.class.getTypeName());
        }
        Assert.assertTrue(hasJsonWebToken, "PrincipalClass has JsonWebToken interface");
    }

    @Test(groups = TEST_GROUP_CDI,
        description = "")
    public void getInjectedClaims() throws Exception {
        String uri = baseURL.toExternalForm() + "/endp/getInjectedClaims";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam(Claims.iss.name(), "https://server.example.com")
            .queryParam(Claims.jti.name(), "a-123")
            .queryParam(Claims.aud.name(), "s6BhdRkqt3")
            .queryParam(Claims.sub.name(), "24400320")
            .queryParam(Claims.raw_token.name(), token)
            .queryParam(Claims.iat.name(), iatClaim)
            .queryParam(Claims.auth_time.name(), authTimeClaim)
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        String reply = response.readEntity(String.class);
        System.out.println(reply);
        // Validate the expected injection tests
        Assert.assertTrue(reply.contains("iss PASS"));
        Assert.assertTrue(reply.contains("jti PASS"));
        Assert.assertTrue(reply.contains("jti-Optional PASS"));
        Assert.assertTrue(reply.contains("jti-Provider PASS"));
        Assert.assertTrue(reply.contains("aud PASS"));
        Assert.assertTrue(reply.contains("iat PASS"));
        Assert.assertTrue(reply.contains("iat-Dupe PASS"));
        Assert.assertTrue(reply.contains("sub-Optional PASS"));
        Assert.assertTrue(reply.contains("auth_time PASS"));
        Assert.assertTrue(reply.contains("raw_token PASS"));
        Assert.assertTrue(reply.contains("custom-missing PASS"));

        // A second request to validate the request scope of injected values
        HashMap<String, Long> timeClaims = new HashMap<>();
        String token2 = TokenUtils.generateTokenString("/RolesEndpoint2.json", null, timeClaims);
        Long iatClaim2 = timeClaims.get(Claims.iat.name());
        Long authTimeClaim2 = timeClaims.get(Claims.auth_time.name());
        WebTarget echoEndpointTarget2 = ClientBuilder.newClient()
            .target(uri)
            .queryParam(Claims.iss.name(), "https://server.example.com")
            .queryParam(Claims.jti.name(), "a-123.2")
            .queryParam(Claims.aud.name(), "s6BhdRkqt3")
            .queryParam(Claims.sub.name(), "24400320#2")
            .queryParam(Claims.raw_token.name(), token2)
            .queryParam(Claims.iat.name(), iatClaim2)
            .queryParam(Claims.auth_time.name(), authTimeClaim2)
            ;
        Response response2 = echoEndpointTarget2.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token2).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response2.getStatus());
        reply = response2.readEntity(String.class);
        System.out.println(reply);
        Assert.assertTrue(reply.contains("iss PASS"));
        Assert.assertTrue(reply.contains("jti PASS"));
        Assert.assertTrue(reply.contains("jti-Optional PASS"));
        Assert.assertTrue(reply.contains("jti-Provider PASS"));
        Assert.assertTrue(reply.contains("aud PASS"));
        Assert.assertTrue(reply.contains("iat PASS"));
        Assert.assertTrue(reply.contains("iat-Dupe PASS"));
        Assert.assertTrue(reply.contains("sub-Optional PASS"));
        Assert.assertTrue(reply.contains("auth_time PASS"));
        Assert.assertTrue(reply.contains("raw_token PASS"));
        Assert.assertTrue(reply.contains("custom-missing PASS"));
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request without an MP-JWT to unsecured endpoint has HTTP_OK")
    public void callHeartbeat() throws Exception {
        String uri = baseURL.toExternalForm() + "/endp/heartbeat";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello")
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        Assert.assertTrue(response.readEntity(String.class).startsWith("Heartbeat:"), "Saw Heartbeat: ...");
    }
}
