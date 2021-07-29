/*
 * Copyright (c) 2016-2021 Contributors to the Eclipse Foundation
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

import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_CDI;

import java.io.IOException;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.tck.util.MpJwtTestVersion;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
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

/**
 * Tests of injection of JsonWebToken claims using {@linkplain org.eclipse.microprofile.jwt.ClaimValue} interface wrappers.
 */
public class ApplicationScopedInjectionTest extends Arquillian {

    /**
     * The test generated JWT token strings
     */
    private static String token1;
    private static String token2;

    /**
     * The base URL for the container under test
     */
    @ArquillianResource
    private URL baseURL;

    /**
     * Create a CDI aware base web application archive
     *
     * @return the base base web application archive
     * @throws IOException - on resource failure
     */
    @Deployment(testable=true)
    public static WebArchive createDeployment() throws IOException {
        URL config = ApplicationScopedInjectionTest.class.getResource("/META-INF/microprofile-config-publickey-location.properties");
        URL publicKey = ApplicationScopedInjectionTest.class.getResource("/publicKey.pem");
        WebArchive webArchive = ShrinkWrap
            .create(WebArchive.class, "ApplicationScopedInjectionTest.war")
            .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_1_0.name()), MpJwtTestVersion.MANIFEST_NAME)
            .addAsResource(publicKey, "/publicKey.pem")
            .addClass(ApplicationScopedEndpoint.class)
            .addClass(TCKApplication.class)
            .addAsWebInfResource("beans.xml", "beans.xml")
            .addAsManifestResource(config, "microprofile-config.properties");
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @BeforeClass(alwaysRun=true)
    public static void generateToken() throws Exception {
        token1 = TokenUtils.generateTokenString("/Token1.json");
        token2 = TokenUtils.generateTokenString("/Token2.json");
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_CDI,
        description = "Verify that the raw token injected as claim value is as expected")
    public void verifyInjectedRawTokenClaimValue() throws Exception {
        Reporter.log("Begin verifyInjectedRawTokenClaimValue\n");
        String uri = baseURL.toExternalForm() + "endp/verifyInjectedRawTokenClaimValue";
        verifyInjectedToken(uri, token1);
        verifyInjectedToken(uri, token2);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_CDI,
        description = "Verify that JsonWebToken.getRawToken returns the raw token as expected")
    public void verifyInjectedRawTokenJwt() throws Exception {
        Reporter.log("Begin verifyInjectedRawTokenJwt\n");
        String uri = baseURL.toExternalForm() + "endp/verifyInjectedRawTokenJwt";
        verifyInjectedToken(uri, token1);
        verifyInjectedToken(uri, token2);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_CDI,
        description = "Verify that the raw token injected as provider is as expected")
    public void verifyInjectedRawToken1Provider() throws Exception {
        Reporter.log("Begin verifyInjectedRawTokenProvider\n");
        String uri = baseURL.toExternalForm() + "endp/verifyInjectedRawTokenProvider";
        verifyInjectedToken(uri, token1);
        verifyInjectedToken(uri, token2);
    }

    private void verifyInjectedToken(String uri, String token) {
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.raw_token.name(), token);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
        Assert.assertEquals(reply.getString("injectedRawToken"), token);
    }
}
