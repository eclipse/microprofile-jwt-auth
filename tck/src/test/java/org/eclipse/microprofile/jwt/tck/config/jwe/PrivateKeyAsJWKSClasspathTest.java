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
package org.eclipse.microprofile.jwt.tck.config.jwe;

import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_CONFIG;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Properties;

import org.eclipse.microprofile.jwt.config.Names;
import org.eclipse.microprofile.jwt.tck.TCKConstants;
import org.eclipse.microprofile.jwt.tck.config.JwksApplication;
import org.eclipse.microprofile.jwt.tck.config.SimpleTokenUtils;
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

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

/**
 * Validate that config property values of type resource path to JWKS works to decrypt the JWT which is encrypted with
 * publicKey4k.jwk
 */
public class PrivateKeyAsJWKSClasspathTest extends Arquillian {

    /**
     * The base URL for the container under test
     */
    @ArquillianResource
    private URL baseURL;

    /**
     * Create a CDI aware base web application archive that includes an embedded PEM public key that is referenced via
     * the mp.jwt.verify.publickey.location as an embedded resource property. The root url is /jwks
     *
     * @return the base base web application archive
     * @throws IOException
     *             - on resource failure
     */
    @Deployment()
    public static WebArchive createLocationDeployment() throws IOException {
        URL publicKey = PrivateKeyAsPEMClasspathTest.class.getResource("/publicKey4k.pem");
        URL decryptorJwk = PrivateKeyAsJWKSClasspathTest.class.getResource("/decryptorPrivateKeySet.jwk");
        // Setup the microprofile-config.properties content
        Properties configProps = new Properties();
        // Location points to the JWKS bundled in the deployment
        configProps.setProperty(Names.VERIFIER_PUBLIC_KEY_LOCATION, "/publicKey4k.pem");
        configProps.setProperty(Names.DECRYPTOR_KEY_LOCATION, "/decryptorPrivateKeySet.jwk");
        configProps.setProperty(Names.ISSUER, TCKConstants.TEST_ISSUER);
        StringWriter configSW = new StringWriter();
        configProps.store(configSW, "PrivateKeyAsJWKSClasspathTest microprofile-config.properties");
        StringAsset configAsset = new StringAsset(configSW.toString());
        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class, "PrivateKeyAsJWKSClasspathTest.war")
                .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_1_2.name()),
                        MpJwtTestVersion.MANIFEST_NAME)
                .addAsResource(publicKey, "/publicKey4k.pem")
                .addAsResource(decryptorJwk, "/decryptorPrivateKeySet.jwk")
                .addClass(PrivateKeyEndpoint.class)
                .addClass(JwksApplication.class)
                .addClass(SimpleTokenUtils.class)
                .addAsWebInfResource("beans.xml", "beans.xml")
                .addAsManifestResource(configAsset, "microprofile-config.properties");
        return webArchive;
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_CONFIG, description = "Validate specifying the mp.jwt.decrypt.key.location as resource path to a JWKS key")
    public void testKeyAsLocation() throws Exception {
        Reporter.log("testKeyAsLocation, expect HTTP_OK");

        PrivateKey signingKey = TokenUtils.readPrivateKey("/privateKey4k.pem");
        PublicKey publicKey = TokenUtils.readJwkPublicKey("/encryptorPublicKey.jwk");
        String kid = "mp-jwt-set";
        String token = TokenUtils.signEncryptClaims(signingKey, null, publicKey, kid, "/Token1.json", true);

        String uri = baseURL.toExternalForm() + "jwks/endp/verifyKeyLocationAsJWKSResource";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("kid", kid);
        Response response =
                echoEndpointTarget.request(APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
}
