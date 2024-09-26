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
package org.eclipse.microprofile.jwt.tck.config;

import static jakarta.ws.rs.core.MediaType.TEXT_PLAIN;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_CONFIG;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;

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
import org.testng.Reporter;
import org.testng.annotations.Test;

import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

/**
 * Validate that if mp.jwt.verify.publickey.algorithm is not configured, then both RS256 and ES256 signatures must be
 * accepted.
 */
public class RsaAndEcSignatureAlgorithmTest extends Arquillian {

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
    @Deployment()
    public static WebArchive createDeployment() throws IOException {
        URL config =
                RsaAndEcSignatureAlgorithmTest.class.getResource("/META-INF/microprofile-config-rsa-ec.properties");

        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class, "RsaAndEcSignatureAlgorithmTest.war")
                .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_2_2.name()),
                        MpJwtTestVersion.MANIFEST_NAME)
                .addClass(RS256OrES256Endpoint.class)
                .addClass(TCKApplication.class)
                .addClass(SimpleTokenUtils.class)
                .addAsWebInfResource("beans.xml", "beans.xml")
                .addAsManifestResource(config, "microprofile-config.properties");
        return webArchive;
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_CONFIG, description = "Validate that the ES256 signed token is accepted")
    public void testES256Token() throws Exception {
        Reporter.log("testES256Token, expect HTTP_OK");

        PrivateKey privateKey = TokenUtils.readECPrivateKey("/ecPrivateKey.pem");
        String kid = "eckey";
        String token = TokenUtils.signClaims(privateKey, kid, "/Token1.json");

        String uri = baseURL.toExternalForm() + "endp/verifyToken";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response =
                echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        Assert.assertEquals("ES256", replyString);
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_CONFIG, description = "Validate that the RS256 signed token is accepted")
    public void testRS256Token() throws Exception {
        Reporter.log("testRS256Token, expect HTTP_OK");

        PrivateKey privateKey = TokenUtils.readECPrivateKey("/privateKey4k.pem");
        String kid = "rskey";
        String token = TokenUtils.signClaims(privateKey, kid, "/Token1.json");

        String uri = baseURL.toExternalForm() + "endp/verifyToken";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response =
                echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        Assert.assertEquals("RS256", replyString);
    }

}
