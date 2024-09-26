/*
 * Copyright (c) 2016-2018 Contributors to the Eclipse Foundation
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

import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_CONFIG;

import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Properties;

import org.eclipse.microprofile.jwt.config.Names;
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
 * Validate the handling of the JWT iss claim.
 *
 * Validate the iss claim against the {@linkplain Names#ISSUER} property is performed, and fails if the jwt iss does not
 * match the {@linkplain Names#ISSUER} property.
 */
public class IssValidationFailTest extends Arquillian {
    /**
     * The base URL for the container under test
     */
    @ArquillianResource
    private URL baseURL;

    /**
     * The token used by the test
     */
    private static String token;

    /**
     * Create a CDI aware base web application archive that includes an embedded PEM public key that is included as the
     * mp.jwt.verify.publickey property. The root url is /
     *
     * @return the base base web application archive
     * @throws Exception
     *             - on resource failure
     */
    @Deployment()
    public static WebArchive createDeployment() throws Exception {
        URL publicKey = IssValidationFailTest.class.getResource("/publicKey4k.pem");

        PrivateKey privateKey = TokenUtils.readPrivateKey("/privateKey4k.pem");
        String kid = "publicKey4k";
        HashMap<String, Long> timeClaims = new HashMap<>();
        token = TokenUtils.generateTokenString(privateKey, kid, "/RequiredClaims.json", null, timeClaims);

        // Setup the microprofile-config.properties content
        Properties configProps = new Properties();
        // Location points to the PEM bundled in the deployment
        configProps.setProperty(Names.VERIFIER_PUBLIC_KEY_LOCATION, "/publicKey4k.pem");
        // Set an invalid mp.jwt.verify.issuer value
        configProps.setProperty(Names.ISSUER, "https://IssValidationFailTest");
        StringWriter configSW = new StringWriter();
        configProps.store(configSW, "IssValidationFailTest microprofile-config.properties");
        StringAsset configAsset = new StringAsset(configSW.toString());

        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class, "IssValidationFailTest.war")
                .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_1_1.name()),
                        MpJwtTestVersion.MANIFEST_NAME)
                .addAsResource(publicKey, "/publicKey.pem")
                .addAsResource(publicKey, "/publicKey4k.pem")
                // Include the token for inspection by ApplicationArchiveProcessor
                .add(new StringAsset(token), "MP-JWT")
                .addClass(PublicKeyEndpoint.class)
                .addClass(TCKApplication.class)
                .addClass(SimpleTokenUtils.class)
                .addAsWebInfResource("beans.xml", "beans.xml")
                .addAsManifestResource(configAsset, "microprofile-config.properties");
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_CONFIG, description = "Validate that JWK with iss that does not match mp.jwt.verify.issuer returns HTTP_UNAUTHORIZED")
    public void testNotRequiredIssMismatchFailure() throws Exception {
        Reporter.log("testNotRequiredIssMismatchFailure, expect HTTP_UNAUTHORIZED");

        String uri = baseURL.toExternalForm() + "endp/verifyIssIsOk";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response =
                echoEndpointTarget.request(APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_UNAUTHORIZED);
    }

}
