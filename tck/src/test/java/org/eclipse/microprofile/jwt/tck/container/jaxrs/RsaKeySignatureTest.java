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

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_JAXRS;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

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

public class RsaKeySignatureTest extends Arquillian {

    /**
     * The test generated JWT token string
     */
    private static String token;

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
        URL config = RsaKeySignatureTest.class.getResource("/META-INF/microprofile-config-rsakey1024-location.properties");
        URL publicKey = RsaKeySignatureTest.class.getResource("/rsaPublicKey1024bit.jwk");
        WebArchive webArchive = ShrinkWrap
            .create(WebArchive.class, "RsaKeySignatureTest.war")
            .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_1_2.name()), MpJwtTestVersion.MANIFEST_NAME)
            .addAsResource(publicKey, "/rsaPublicKey1024bit.jwk")
            .addClass(RolesEndpoint.class)
            .addClass(TCKApplication.class)
            .addAsWebInfResource("beans.xml", "beans.xml")
            .addAsManifestResource(config, "microprofile-config.properties");
        return webArchive;
    }

    @BeforeClass(alwaysRun=true)
    public static void generateToken() throws Exception {
        RSAPrivateKey privateKey = (RSAPrivateKey)TokenUtils.readJwkPrivateKey("/rsaPrivateKey1024bit.jwk");
        Assert.assertEquals(privateKey.getModulus().bitLength(), 1024);
        RSAPublicKey publicKey = (RSAPublicKey)TokenUtils.readJwkPublicKey("/rsaPublicKey1024bit.jwk");
        Assert.assertEquals(publicKey.getModulus().bitLength(), 1024);
        token = TokenUtils.signClaims(privateKey, "1024bit", "/Token1.json");
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS,
        description = "Validate a request with MP-JWT succeeds with HTTP_OK, and replies with hello, user={token upn claim}")
    public void callEcho() throws Exception {
        Reporter.log("callEcho, expect HTTP_OK");

        String uri = baseURL.toExternalForm() + "endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("input", "hello");
        
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        // Must return hello, user={token upn claim}
        Assert.assertEquals(reply, "hello, user=jdoe@example.com");
    }
}
