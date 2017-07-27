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
package org.eclipse.microprofile.jwt.tck.roles;

import org.eclipse.microprofile.jwt.JWTPrincipal;
import org.eclipse.microprofile.jwt.impl.DefaultJWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.tck.cdi.JWTAuthContextInfoProvider;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.modules.maven.ArtifactCoordinates;
import org.jboss.modules.maven.MavenResolver;
import org.jboss.shrinkwrap.api.Filters;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.security.enterprise.CallerPrincipal;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;

@RunWith(Arquillian.class)
public class RolesAllowedTest {

    @ArquillianResource
    private URL baseURL;

    @Deployment(testable = false)
    public static WebArchive createDeployment() throws IOException {
        MavenResolver resolver = MavenResolver.createDefaultResolver();
        File core = resolver.resolveJarArtifact(ArtifactCoordinates.fromString("org.keycloak:keycloak-core:3.2.0.Final"));
        File common = resolver.resolveJarArtifact(ArtifactCoordinates.fromString("org.keycloak:keycloak-common:3.2.0.Final"));
        File ri = resolver.resolveJarArtifact(ArtifactCoordinates.fromString("org.eclipse.microprofile.jwt:jwt-auth-ri:1.0-SNAPSHOT"));
        File bc = resolver.resolveJarArtifact(ArtifactCoordinates.fromString("org.bouncycastle:bcprov-jdk15on:1.52"));
        URL privateKey = RolesAllowedTest.class.getResource("/privateKey.pem");
        URL publicKey = RolesAllowedTest.class.getResource("/publicKey.pem");
        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class)
                .addAsLibraries(core, common, ri, bc)
                .addAsResource(privateKey, "/privateKey.pem")
                .addAsResource(publicKey, "/publicKey.pem")
                .addPackages(true, Filters.exclude(".*Test.*"),
                        RolesEndpoint.class.getPackage())
                .addPackage(JWTCallerPrincipal.class.getPackage())
                .addClass(JWTAuthContextInfoProvider.class)
                .addClass(JWTPrincipal.class)
                .addClass(CallerPrincipal.class)
                .addAsServiceProvider(JWTCallerPrincipalFactory.class, DefaultJWTCallerPrincipalFactory.class)
                .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml")
                .addAsWebInfResource("WEB-INF/web.xml", "web.xml");
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @Test
    public void callEcho() throws Exception {
        String token = TokenUtils.generateTokenString("/RolesEndpoint.json");
        System.out.printf("jwt: %s\n", token);

        String uri = baseURL.toExternalForm() + "/endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello")
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        Assert.assertEquals("hello, user=jdoe@example.com", response.readEntity(String.class));
    }

    @Test
    public void callEcho2() throws Exception {
        String token = TokenUtils.generateTokenString("/RolesEndpoint.json");
        System.out.printf("jwt: %s\n", token);

        String uri = baseURL.toExternalForm() + "/endp/echo2";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello")
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_FORBIDDEN, response.getStatus());
    }
}
