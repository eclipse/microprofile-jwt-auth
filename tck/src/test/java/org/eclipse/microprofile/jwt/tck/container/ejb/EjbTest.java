/*
 * Copyright (c) 2016-2017 Contributors to the Eclipse Foundation
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
package org.eclipse.microprofile.jwt.tck.container.ejb;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.TCKConstants;
import org.eclipse.microprofile.jwt.tck.container.jaxrs.TCKApplication;
import org.eclipse.microprofile.jwt.tck.util.MpJwtTestVersion;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;

/**
 * Basic EJB container integration tests
 */
public class EjbTest extends Arquillian {

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
        URL publicKey = EjbTest.class.getResource("/publicKey.pem");
        WebArchive webArchive = ShrinkWrap
            .create(WebArchive.class, "EjbTest.war")
            .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_1_0.name()), MpJwtTestVersion.MANIFEST_NAME)
            .addAsResource(publicKey, "/publicKey.pem")
            .addClass(EjbEndpoint.class)
            .addClass(IService.class)
            .addClass(ServiceEJB.class)
            .addClass(TCKApplication.class)
            .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml")
            ;
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @BeforeClass(alwaysRun = true)
    public static void generateToken() throws Exception {
        token = TokenUtils.generateTokenString("/Token1.json");
    }

    @RunAsClient
    @Test(groups = TCKConstants.TEST_GROUP_EJB,
        description = "Validate a request with MP-JWT to a secured method propagates to a secured ejb method")
    public void callEjbEcho() throws Exception {
        String uri = baseURL.toExternalForm() + "endp/getEJBEcho";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        System.out.println(reply);
    }

    @RunAsClient
    @Test(groups = TCKConstants.TEST_GROUP_EJB,
        description = "Validate a request with MP-JWT PolicyContext.getContext() Subject has a JsonWebToken")
    public void getSubjectClass() throws Exception {
        String uri = baseURL.toExternalForm() + "endp/getEJBSubjectClass";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        System.out.println(reply);
    }

    @RunAsClient
    @Test(groups = TCKConstants.TEST_GROUP_EJB,
        description = "Validate a request with MP-JWT SecurityContext.getUserPrincipal() is a JsonWebToken")
    public void testEJBPrincipalClass() throws Exception {
        String uri = baseURL.toExternalForm() + "endp/getEJBPrincipalClass";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri)
            ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        String[] ifaces = reply.split(",");
        boolean hasJsonWebToken = false;
        for(String iface : ifaces) {
            hasJsonWebToken |= iface.equals(JsonWebToken.class.getTypeName());
        }
        Assert.assertTrue(hasJsonWebToken, "EJB PrincipalClass has JsonWebToken interface");
    }

}
