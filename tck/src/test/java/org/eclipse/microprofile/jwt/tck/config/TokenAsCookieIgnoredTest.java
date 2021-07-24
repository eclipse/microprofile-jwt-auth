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
package org.eclipse.microprofile.jwt.tck.config;

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;
import static org.eclipse.microprofile.jwt.config.Names.ISSUER;
import static org.eclipse.microprofile.jwt.config.Names.TOKEN_COOKIE;
import static org.eclipse.microprofile.jwt.config.Names.VERIFIER_PUBLIC_KEY_LOCATION;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_CONFIG;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_JAXRS;

import java.io.IOException;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Properties;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import org.eclipse.microprofile.jwt.tck.TCKConstants;
import org.eclipse.microprofile.jwt.tck.container.jaxrs.InvalidTokenTest;
import org.eclipse.microprofile.jwt.tck.container.jaxrs.RolesEndpoint;
import org.eclipse.microprofile.jwt.tck.container.jaxrs.TCKApplication;
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

public class TokenAsCookieIgnoredTest extends Arquillian {
    @ArquillianResource
    private URL baseURL;

    @Deployment
    public static WebArchive createDeployment() throws IOException {
        Properties configProps = new Properties();
        configProps.setProperty(VERIFIER_PUBLIC_KEY_LOCATION, "/publicKey.pem");
        configProps.setProperty(ISSUER, TCKConstants.TEST_ISSUER);
        configProps.setProperty(TOKEN_COOKIE, "jwt");
        StringWriter configSW = new StringWriter();
        configProps.store(configSW, "TokenAsCookieIgnoredTest microprofile-config.properties");
        StringAsset config = new StringAsset(configSW.toString());

        URL publicKey = InvalidTokenTest.class.getResource("/publicKey.pem");
        return ShrinkWrap
                .create(WebArchive.class, "TokenAsCookieIgnored.war")
                .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_1_2.name()),
                        MpJwtTestVersion.MANIFEST_NAME)
                .addAsResource(publicKey, "/publicKey.pem")
                .addClass(TCKApplication.class)
                .addClass(RolesEndpoint.class)
                .addAsWebInfResource("beans.xml", "beans.xml")
                .addAsManifestResource(config, "microprofile-config.properties");
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_CONFIG, description = "Validate a request with a valid JWT in a Cookie but no Token Header set fails with "
            +
            "HTTP_UNAUTHORIZED")
    public void noTokenHeaderSetToCookie() throws Exception {
        String token = TokenUtils.generateTokenString("/Token1.json");

        String uri = baseURL.toExternalForm() + "endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello");
        Response response = echoEndpointTarget
                .request(TEXT_PLAIN)
                .cookie("jwt", token)
                .get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_UNAUTHORIZED);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with a valid JWT")
    public void validJwt() throws Exception {
        String token = TokenUtils.generateTokenString("/Token1.json");

        String uri = baseURL.toExternalForm() + "endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello");
        Response response = echoEndpointTarget
                .request(TEXT_PLAIN)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        Assert.assertEquals(reply, "hello, user=jdoe@example.com");
    }
}
