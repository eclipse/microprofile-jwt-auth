/*
 * Copyright (c) 2016-2022 Contributors to the Eclipse Foundation
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

import static jakarta.ws.rs.core.MediaType.TEXT_PLAIN;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_JAXRS;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashSet;

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
import org.testng.annotations.Test;

import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

/**
 * These set of tests validate the validation expectations for JWTs
 */
public class InvalidTokenTest extends Arquillian {
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
        URL config = InvalidTokenTest.class.getResource("/META-INF/microprofile-config-publickey-location.properties");
        URL publicKey = InvalidTokenTest.class.getResource("/publicKey.pem");
        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class, "InvalidTokenTest.war")
                .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_1_0.name()),
                        MpJwtTestVersion.MANIFEST_NAME)
                .addAsResource(publicKey, "/publicKey.pem")
                .addClass(RolesEndpoint.class)
                .addClass(TCKApplication.class)
                .addAsWebInfResource("beans.xml", "beans.xml")
                .addAsManifestResource(config, "microprofile-config.properties");
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with expired token fails with HTTP_UNAUTHORIZED")
    public void callEchoExpiredToken() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.EXP);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);

        callEchoAndExpectUnauthorized(token);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with an non-matching issuer fails with HTTP_UNAUTHORIZED")
    public void callEchoBadIssuer() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.ISSUER);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);

        callEchoAndExpectUnauthorized(token);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with an incorrect signer fails with HTTP_UNAUTHORIZED")
    public void callEchoBadSigner() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.SIGNER);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);

        callEchoAndExpectUnauthorized(token);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with an incorrect signature algorithm fails with HTTP_UNAUTHORIZED")
    public void callEchoBadSignerAlg() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.ALG);
        String token = TokenUtils.generateTokenString("/Token1.json", invalidFields);

        callEchoAndExpectUnauthorized(token);
    }

    private void callEchoAndExpectUnauthorized(String token) throws Exception {
        System.out.printf("jwt: %s\n", token);

        String uri = baseURL.toExternalForm() + "endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello");
        Response response = echoEndpointTarget.request(TEXT_PLAIN)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_UNAUTHORIZED);
        String reply = response.readEntity(String.class);
        System.out.printf("Reply: %s\n", reply);
    }

}
