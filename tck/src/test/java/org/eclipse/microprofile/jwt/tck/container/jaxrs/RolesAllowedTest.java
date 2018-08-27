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
import org.eclipse.microprofile.jwt.tck.TCKConstants;
import org.eclipse.microprofile.jwt.tck.util.MpJwtTestVersion;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.Assert;
import org.testng.Reporter;
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

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_CDI;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_EE_SECURITY;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_JAXRS;

/**
 * Tests of the MP-JWT auth method authorization behavior as expected by the MP-JWT RBAC 1.0 spec
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
            .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_1_0.name()), MpJwtTestVersion.MANIFEST_NAME)
            .addAsResource(publicKey, "/publicKey.pem")
            .addClass(RolesEndpoint.class)
            .addClass(TCKApplication.class)
            .addAsWebInfResource("beans.xml", "beans.xml")
            ;
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @BeforeClass(alwaysRun=true)
    public static void generateToken() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        token = TokenUtils.generateTokenString("/Token1.json", null, timeClaims);
        iatClaim = timeClaims.get(Claims.iat.name());
        authTimeClaim = timeClaims.get(Claims.auth_time.name());
        expClaim = timeClaims.get(Claims.exp.name());
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with no token fails with HTTP_UNAUTHORIZED")
    public void callEchoNoAuth() throws Exception {
        Reporter.log("callEchoNoAuth, expect HTTP_UNAUTHORIZED");
        String uri = baseURL.toExternalForm() + "endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello")
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_UNAUTHORIZED);
    }

    @RunAsClient
    @Test(groups = TCKConstants.TEST_GROUP_JAXRS,
        description = "Attempting access with BASIC auth header should fail with HTTP_UNAUTHORIZED")
    public void callEchoBASIC() throws Exception {
        Reporter.log("callEchoBASIC, expect HTTP_UNAUTHORIZED");
        byte[] tokenb = Base64.getEncoder().encode("jdoe@example.com:password".getBytes());
        String token = new String(tokenb);
        System.out.printf("basic: %s\n", token);

        String uri = baseURL.toExternalForm() + "endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello")
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "BASIC "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_UNAUTHORIZED);
        String reply = response.readEntity(String.class);
        System.out.println(reply);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS,
        description = "Validate a request with MP-JWT succeeds with HTTP_OK, and replies with hello, user={token upn claim}")
    public void callEcho() throws Exception {
        Reporter.log("callEcho, expect HTTP_OK");

        String uri = baseURL.toExternalForm() + "endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello")
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        // Must return hello, user={token upn claim}
        Assert.assertEquals(reply, "hello, user=jdoe@example.com");
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with MP-JWT but no associated role fails with HTTP_FORBIDDEN")
    public void callEcho2() throws Exception {
        Reporter.log("callEcho2, expect HTTP_FORBIDDEN");

        String uri = baseURL.toExternalForm() + "endp/echo2";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello")
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        String reply = response.readEntity(String.class);
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_FORBIDDEN);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with MP-JWT is able to access checkIsUserInRole with HTTP_OK")
    public void checkIsUserInRole() throws Exception {
        Reporter.log("checkIsUserInRole, expect HTTP_OK");

        String uri = baseURL.toExternalForm() + "endp/checkIsUserInRole";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        String reply = response.readEntity(String.class);
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with MP-JWT Token2 fails to access checkIsUserInRole with HTTP_FORBIDDEN")
    public void checkIsUserInRoleToken2() throws Exception {
        Reporter.log("checkIsUserInRoleToken2, expect HTTP_FORBIDDEN");
        String token2 = TokenUtils.generateTokenString("/Token2.json");

        String uri = baseURL.toExternalForm() + "endp/checkIsUserInRole";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token2).get();
        String reply = response.readEntity(String.class);
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_FORBIDDEN);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with MP-JWT Token2 is able to access echoNeedsToken2Role with HTTP_OK")
    public void echoNeedsToken2Role() throws Exception {
        Reporter.log("echoNeedsToken2Role, expect HTTP_FORBIDDEN");
        String token2 = TokenUtils.generateTokenString("/Token2.json");

        String uri = baseURL.toExternalForm() + "endp/echoNeedsToken2Role";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello")
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token2).get();
        String reply = response.readEntity(String.class);
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with MP-JWT Token2 calling echo fails with HTTP_FORBIDDEN")
    public void echoWithToken2() throws Exception {
        Reporter.log("echoWithToken2, expect HTTP_FORBIDDEN");
        String token2 = TokenUtils.generateTokenString("/Token2.json");

        String uri = baseURL.toExternalForm() + "endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello")
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token2).get();
        String reply = response.readEntity(String.class);
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_FORBIDDEN);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS,
        description = "Validate a request with MP-JWT SecurityContext.getUserPrincipal() is a JsonWebToken")
    public void getPrincipalClass() throws Exception {
        Reporter.log("getPrincipalClass, expect HTTP_OK");
        String uri = baseURL.toExternalForm() + "endp/getPrincipalClass";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        Assert.assertEquals(reply, "isJsonWebToken:true");
    }

    /**
     * This test requires that the server provide a mapping from the group1 grant in the token to a Group1MappedRole
     * application declared role.
     */
    @RunAsClient
    @Test(groups = TEST_GROUP_EE_SECURITY,
        description = "Validate a request without an MP-JWT to endpoint requiring role mapping has HTTP_OK")
    public void testNeedsGroup1Mapping() {
        Reporter.log("testNeedsGroup1Mapping, expect HTTP_OK");
        String uri = baseURL.toExternalForm() + "endp/needsGroup1Mapping";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        System.out.println(reply);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_CDI,
        description = "Validate that accessing secured method has HTTP_OK and injected JsonWebToken principal")
    public void getInjectedPrincipal() throws Exception {
        Reporter.log("getInjectedPrincipal, expect HTTP_OK");
        String uri = baseURL.toExternalForm() + "endp/getInjectedPrincipal";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        Assert.assertEquals(reply, "isJsonWebToken:true");
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS,
        description = "Validate a request without an MP-JWT to unsecured endpoint has HTTP_OK with expected response")
    public void callHeartbeat() throws Exception {
        Reporter.log("callHeartbeat, expect HTTP_OK");
        String uri = baseURL.toExternalForm() + "endp/heartbeat";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello")
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        Assert.assertTrue(reply.startsWith("Heartbeat:"), "Saw Heartbeat: ...");
    }
}
