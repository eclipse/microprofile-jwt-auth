/*
 * Copyright (c) 2022 Contributors to the Eclipse Foundation
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
package org.eclipse.microprofile.jwt.tck.container.jaxrs.jwe;

import static jakarta.ws.rs.core.MediaType.TEXT_PLAIN;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_JAXRS;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.eclipse.microprofile.jwt.tck.container.jaxrs.RolesEndpoint;
import org.eclipse.microprofile.jwt.tck.container.jaxrs.TCKApplication;
import org.eclipse.microprofile.jwt.tck.util.KeyManagementAlgorithm;
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
 * If "mp.jwt.decryption.algorithm" is not set then both RSA-OAEP and RSA-OAEP-256 must be accepted.
 */
public class DecryptKeyAlgorithmDefaultTest extends Arquillian {

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
        URL config = DecryptKeyAlgorithmDefaultTest.class
                .getResource("/META-INF/microprofile-config-verify-decrypt-algorithm-default.properties");
        URL verifyKey = DecryptKeyAlgorithmDefaultTest.class.getResource("/publicKey4k.pem");
        URL decryptKey = DecryptKeyAlgorithmDefaultTest.class.getResource("/privateKey.pem");
        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class, "DecryptKeyAlgorithmDefaultTest.war")
                .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_2_1.name()),
                        MpJwtTestVersion.MANIFEST_NAME)
                .addAsResource(decryptKey, "/privateKey.pem")
                .addAsResource(verifyKey, "/publicKey4k.pem")
                .addClass(RolesEndpoint.class)
                .addClass(TCKApplication.class)
                .addAsWebInfResource("beans.xml", "beans.xml")
                .addAsManifestResource(config, "microprofile-config.properties");
        return webArchive;
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with RSA-OAEP-256 encrypted token succeeds")
    public void callEchoRsaOaep256() throws Exception {
        Reporter.log("callEcho with RSA-OAEP-256 encrypted token, expect HTTP_OK");

        PrivateKey signingKey = TokenUtils.readPrivateKey("/privateKey4k.pem");
        PublicKey encryptionKey = TokenUtils.readPublicKey("/publicKey.pem");
        String token =
                TokenUtils.signEncryptClaims(signingKey, null, encryptionKey, KeyManagementAlgorithm.RSA_OAEP_256, null,
                        "/Token1.json", true);

        String uri = baseURL.toExternalForm() + "endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello");
        Response response =
                echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        // Must return hello, user={token upn claim}
        Assert.assertEquals(reply, "hello, user=jdoe@example.com");
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_JAXRS, description = "Validate a request with RSA-OAEP encrypted token succeeds")
    public void callEchoRsaOaep() throws Exception {
        Reporter.log("callEcho with RSA-OAEP encrypted token, expect HTTP_OK");

        PrivateKey signingKey = TokenUtils.readPrivateKey("/privateKey4k.pem");
        PublicKey encryptionKey = TokenUtils.readPublicKey("/publicKey.pem");
        String token =
                TokenUtils.signEncryptClaims(signingKey, null, encryptionKey, KeyManagementAlgorithm.RSA_OAEP, null,
                        "/Token1.json", true);

        String uri = baseURL.toExternalForm() + "endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello");
        Response response =
                echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        // Must return hello, user={token upn claim}
        Assert.assertEquals(reply, "hello, user=jdoe@example.com");
    }

}
