/*
 * Copyright (c) 2016-2020 Contributors to the Eclipse Foundation
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

import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_JWT;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_ISSUER;

import java.io.IOException;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.tck.util.MpJwtTestVersion;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils.InvalidClaims;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * Test to ensure that a MP-JWT containing only the minimum set of claims required by the specification can deploy and
 * be used safely without a validation error
 */
public class RequiredClaimsTest extends Arquillian {

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
     *
     * @return the base base web application archive
     * @throws IOException
     *             - on resource failure
     */
    @Deployment(testable = true)
    public static WebArchive createDeployment() throws IOException {
        URL config =
                RequiredClaimsTest.class.getResource("/META-INF/microprofile-config-publickey-location.properties");
        URL publicKey = RequiredClaimsTest.class.getResource("/publicKey.pem");
        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class, "RequiredClaimsTest.war")
                .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_1_0.name()),
                        MpJwtTestVersion.MANIFEST_NAME)
                .addAsResource(publicKey, "/publicKey.pem")
                .addClass(RequiredClaimsEndpoint.class)
                .addClass(TCKApplication.class)
                .addAsWebInfResource("beans.xml", "beans.xml")
                .addAsManifestResource(config, "microprofile-config.properties");
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @BeforeClass(alwaysRun = true)
    public static void generateToken() throws Exception {
        Map<String, Long> timeClaims = new HashMap<>();
        token = TokenUtils.generateTokenString("/RequiredClaims.json", null, timeClaims);
        iatClaim = timeClaims.get(Claims.iat.name());
        authTimeClaim = timeClaims.get(Claims.auth_time.name());
        expClaim = timeClaims.get(Claims.exp.name());
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JWT, description = "Verify that the token issuer claim is as expected")
    public void verifyIssuerClaim() throws Exception {
        Reporter.log("Begin verifyIssuerClaim");
        String uri = baseURL.toExternalForm() + "endp/verifyIssuer";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.iss.name(), TEST_ISSUER)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JWT, description = "Verify that the token sub claim is as expected")
    public void verifySubClaim() throws Exception {
        Reporter.log("Begin verifySubClaim");
        String uri = baseURL.toExternalForm() + "endp/verifySUB";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.sub.name(), "24400320")
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JWT, description = "Verify that the jti claim is as expected")
    public void verifyJTI() throws Exception {
        Reporter.log("Begin verifyJTI\n");
        String uri = baseURL.toExternalForm() + "endp/verifyJTI";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.jti.name(), "a-f2b2180c")
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JWT, description = "Verify that the uPN claim is as expected")
    public void verifyUPN() throws Exception {
        Reporter.log("Begin verifyUPN\n");
        String uri = baseURL.toExternalForm() + "endp/verifyUPN";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.upn.name(), "jdoe@example.com")
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JWT, description = "Verify that the aud claim is as expected")
    public void verifyAudience() throws Exception {
        Reporter.log("Begin verifyAudience\n");
        String uri = baseURL.toExternalForm() + "endp/verifyAudience";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.aud.name(), null)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JWT, description = "Verify that the aud claim is as expected")
    public void verifyOptionalAudience() throws Exception {
        Reporter.log("Begin verifyOptionalAudience\n");
        String uri = baseURL.toExternalForm() + "endp/verifyOptionalAudience";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.aud.name(), null)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JWT, description = "Verify that the iat claim is as expected")
    public void verifyIssuedAt() throws Exception {
        Reporter.log("Begin verifyIssuedAt\n");
        String uri = baseURL.toExternalForm() + "endp/verifyIssuedAt";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.iat.name(), iatClaim)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JWT, description = "Verify that the exp claim is as expected")
    public void verifyExpiration() throws Exception {
        Reporter.log("Begin verifyExpiration\n");
        String uri = baseURL.toExternalForm() + "endp/verifyExpiration";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.exp.name(), expClaim)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JWT, description = "Verify that HTTP 401 status is returned if the token contains no exp claim")
    public void verifyTokenWithoutExpiration() throws Exception {
        PrivateKey pk = TokenUtils.readPrivateKey("/privateKey.pem");
        String tokenWithoutExp =
                TokenUtils.signClaims(pk, "1", "/TokenWithoutExp.json", Collections.singleton(InvalidClaims.EXP), null);
        Reporter.log("Begin verifyTokenWithoutExpiration\n");
        String uri = baseURL.toExternalForm() + "endp/verifyTokenWithoutExpiration";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION,
                "Bearer " + tokenWithoutExp).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_UNAUTHORIZED);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JWT, description = "Verify that HTTP 401 status is returned if the token contains no 'upn', 'preferred_username' and 'sub' claims")
    public void verifyTokenWithoutName() throws Exception {
        String tokenWithoutName = TokenUtils.signClaims("/TokenWithoutName.json");
        Reporter.log("Begin verifyTokenWithoutName\n");
        String uri = baseURL.toExternalForm() + "endp/verifyTokenWithoutName";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION,
                "Bearer " + tokenWithoutName).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_UNAUTHORIZED);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JWT, description = "Verify that HTTP 401 status is returned if the token 'iat' claim is older than 'exp' claim")
    public void verifyTokenWithIatOlderThanExp() throws Exception {
        PrivateKey pk = TokenUtils.readPrivateKey("/privateKey.pem");
        String tokenWithIatOlderThanExp =
                TokenUtils.signClaims(pk, "1", "/TokenWithIatOlderThanExp.json",
                        Collections.singleton(InvalidClaims.IAT), null);
        Reporter.log("Begin verifyTokenWithIatOlderThanExp\n");
        String uri = baseURL.toExternalForm() + "endp/verifyTokenWithIatOlderThanExp";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION,
                "Bearer " + tokenWithIatOlderThanExp).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_UNAUTHORIZED);
    }
}
