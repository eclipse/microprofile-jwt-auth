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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Properties;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import org.eclipse.microprofile.jwt.config.Names;
import org.eclipse.microprofile.jwt.tck.TCKConstants;
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

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_CONFIG;

/**
 * Validate that config property values of type file URL to PEM works to validate the JWT
 * which is signed with privateKey4k.pem
 */
public class PublicKeyAsFileLocationURLTest extends Arquillian {

    /**
     * The base URL for the container under test
     */
    @ArquillianResource
    private URL baseURL;

    /**
     * Create a CDI aware base web application archive that includes an embedded PEM public key that
     * is referenced via the mp.jwt.verify.publickey.location as a URL resource property.
     * The root url is /pem
     * @return the base base web application archive
     * @throws IOException - on resource failure
     */
    @Deployment()
    public static WebArchive createLocationURLDeployment() throws IOException {
        File tmp = File.createTempFile("tck", "pem");
        FileOutputStream writer = new FileOutputStream(tmp);
        URL publicKey = PublicKeyAsFileLocationURLTest.class.getResource("/publicKey4k.pem");
        InputStream reader = publicKey.openStream();
        byte[] data = new byte[1024];
        int bytes = reader.read(data);
        while(bytes > 0) {
            writer.write(data, 0, bytes);
            bytes = reader.read(data);
        }
        reader.close();
        writer.close();

        // Setup the microprofile-config.properties content
        Properties configProps = new Properties();
        // Location points to the PEM file
        configProps.setProperty(Names.VERIFIER_PUBLIC_KEY_LOCATION, tmp.toURI().toASCIIString());
        configProps.setProperty(Names.ISSUER, TCKConstants.TEST_ISSUER);
        StringWriter configSW = new StringWriter();
        configProps.store(configSW, "PublicKeyAsFileLocationURLTest microprofile-config.properties");
        StringAsset configAsset = new StringAsset(configSW.toString());
        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class, "PublicKeyAsFileLocationURLTest.war")
                .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_1_1.name()), MpJwtTestVersion.MANIFEST_NAME)
                .addAsResource(publicKey, "/publicKey4k.pem")
                .addAsResource(publicKey, "/publicKey.pem")
                .addClass(PublicKeyEndpoint.class)
                .addClass(PEMApplication.class)
                .addClass(SimpleTokenUtils.class)
                .addAsWebInfResource("beans.xml", "beans.xml")
                .addAsManifestResource(configAsset, "microprofile-config.properties");
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_CONFIG,
        description = "Validate specifying the mp.jwt.verify.publickey.location as file URL to a PEM key")
    public void testKeyAsLocationUrl() throws Exception {
        Reporter.log("testKeyAsLocationUrl, expect HTTP_OK");

        PrivateKey privateKey = TokenUtils.readPrivateKey("/privateKey4k.pem");
        String kid = "publicKey4k";
        HashMap<String, Long> timeClaims = new HashMap<>();
        String token = TokenUtils.generateTokenString(privateKey, kid, "/Token1.json", null, timeClaims);

        String uri = baseURL.toExternalForm() + "pem/endp/verifyKeyLocationAsPEMUrl";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            .queryParam("kid", kid)
            ;
        Response response = echoEndpointTarget.request(APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
}
