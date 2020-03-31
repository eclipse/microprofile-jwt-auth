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
package org.eclipse.microprofile.jwt.tck.container.jaxrs;

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

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_JAXRS;

public class EmptyTokenTest extends Arquillian {
    @ArquillianResource
    private URL baseURL;

    @Deployment
    public static WebArchive createDeployment() {
        URL config = InvalidTokenTest.class.getResource("/META-INF/microprofile-config-publickey-location.properties");
        URL publicKey = InvalidTokenTest.class.getResource("/publicKey.pem");
        return ShrinkWrap
            .create(WebArchive.class, "EmptyTokenTest.war")
            .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_1_2.name()), MpJwtTestVersion.MANIFEST_NAME)
            .addAsResource(publicKey, "/publicKey.pem")
            .addClass(TCKApplication.class)
            .addClass(EmptyTokenEndpoint.class)
            .addAsWebInfResource("beans.xml", "beans.xml")
            .addAsManifestResource(config, "microprofile-config.properties");
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS,
          description = "Validate that an empty JWT in injected in the endpoint")
    public void emptyToken() {
        String uri = baseURL.toExternalForm() + "endp/verifyEmptyToken";
        WebTarget echoEndpointTarget = ClientBuilder.newClient().target(uri);
        Response response = echoEndpointTarget.request(TEXT_PLAIN).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Assert.assertTrue(reply.getBoolean("pass"));
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS,
          description = "Validate that a token sent to an unauthenticated / unauthorized endpoint is verified")
    public void invalidToken() {
        String uri = baseURL.toExternalForm() + "endp/verifyEmptyToken";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                                                    .target(uri)
                                                    .queryParam("input", "hello");
        Response response = echoEndpointTarget
            .request(TEXT_PLAIN)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + "something")
            .get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_UNAUTHORIZED);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS,
          description = "Validate that a token sent to an unauthenticated / unauthorized endpoint is verified and " +
                        "injected as non-empty")
    public void validToken() throws Exception {
        String token = TokenUtils.generateTokenString("/Token1.json");
        String uri = baseURL.toExternalForm() + "endp/verifyNonEmptyToken";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                                                    .target(uri)
                                                    .queryParam("input", "hello");
        Response response = echoEndpointTarget
            .request(TEXT_PLAIN)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Assert.assertTrue(reply.getBoolean("pass"));
    }
}
