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
package jwks;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.keys.BigEndianBigInteger;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

public abstract class AbstractJWKSTest {
    private static String endpoint;
    private static final String TEST_ISSUER = "https://server.example.com";

    /**
     * Start an embedded HttpServer that returns the test JWKS from a http://localhost:8080/jwks endpoint
     * @throws IOException - on failure
     */
    @BeforeSuite
    public static void startHttpServer() throws IOException {
        // Load the test JKWS from the signer-keyset.jwk resource
        InputStream is = AbstractJWKSTest.class.getResourceAsStream("/signer-keyset.jwk");
        byte[] response;
        StringWriter sw = new StringWriter();
        try(BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
            String line = br.readLine();
            while(line != null) {
                sw.write(line);
                sw.write('\n');
                line = br.readLine();
            }
        }
        response = sw.toString().getBytes();

        // Start a server listening on 8080 with a /jwks context that returns the JWKS json data
        HttpServer httpServer = HttpServer.create(new InetSocketAddress(8080), 0);
        endpoint = "http://localhost:8080/jwks";
        httpServer.createContext("/jwks", new HttpHandler() {
            public void handle(HttpExchange exchange) throws IOException {
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, response.length);
                exchange.getResponseBody().write(response);
                exchange.close();
                System.out.printf("Handled jwks request\n");
            }
        });
        httpServer.start();
        System.out.printf("Started HttpServer at: %s\n", endpoint);
    }

    /**
     * Loads the signer-keypair.jwk resource that was generated using https://mkjwk.org
     * and returns the private key
     *
     * @return the private key from the key pair
     */
    static PrivateKey loadPrivateKey() throws Exception {
        String jwk = TokenUtils.readResource("/signer-keypair.jwk");
        RsaJsonWebKey rsaJsonWebKey = (RsaJsonWebKey) JsonWebKey.Factory.newJwk(jwk);
        RSAPublicKey pk = rsaJsonWebKey.getRsaPublicKey();
        String e = new String(Base64.getUrlEncoder().withoutPadding().encode(pk.getPublicExponent().toByteArray()));
        byte[] nbytes = pk.getModulus().toByteArray();
        if(nbytes[0] == 0 && nbytes.length > 1) {
            byte[] tmp = new byte[nbytes.length-1];
            System.arraycopy(nbytes, 1, tmp, 0, tmp.length);
            nbytes = tmp;
        }
        String n = new String(Base64.getUrlEncoder().withoutPadding().encode(nbytes));
        System.out.printf("e: %s\n", e);
        System.out.printf("n: %s\n", n);
        n = BigEndianBigInteger.toBase64Url(pk.getModulus());
        System.out.printf("n: %s\n", n);
        return rsaJsonWebKey.getRsaPrivateKey();
    }

    /**
     * Validate access to the http://localhost:8080/jwks endpoint
     * @throws IOException - on failure
     */
    @Test
    public void validateGet() throws IOException {
        URL jwksURL = new URL(endpoint);
        InputStream is = jwksURL.openStream();
        try(BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
            String line = br.readLine();
            while(line != null) {
                System.out.println(line);
                line = br.readLine();
            }
        }
    }

    /**
     * Ensure a valid token is validated by the provider using the JWKS URL for the public key associated
     * with the signer.
     *
     * @throws Exception
     */
    @Test
    public void testValidToken() throws Exception {
        PrivateKey pk = loadPrivateKey();
        String token = TokenUtils.generateTokenString(pk, "jwk-test", "/Token1.json", null, null);
        int expGracePeriodSecs = 60;
        validateToken(token, new URL(endpoint), TEST_ISSUER, expGracePeriodSecs);
    }
    /**
     * Ensure a token is validated by the provider using the JWKS URL for the public key associated
     * with the signer.
     *
     * @throws Exception
     */
    @Test(expectedExceptions = {InvalidJwtException.class, BadJOSEException.class, JWTVerificationException.class})
    public void testNoMatchingKID() throws Exception {
        PrivateKey pk = loadPrivateKey();
        String token = TokenUtils.generateTokenString(pk, "invalid-kid", "/Token1.json", null, null);
        int expGracePeriodSecs = 60;
        validateToken(token, new URL(endpoint), TEST_ISSUER, expGracePeriodSecs);
    }

    /**
     * This method is implemented by the JWT provider library to validate the token
     *
     * @param token - the signed, base64 encoded header.content.sig JWT string
     * @param jwksURL - URL to a JWKS that contains the public key to verify the JWT signature
     * @param issuer - the expected iss claim value
     * @param expGracePeriodSecs - grace period in seconds for evaluating the exp claim
     * @throws Exception
     */
    abstract protected void validateToken(String token, URL jwksURL, String issuer, int expGracePeriodSecs)
        throws Exception;

}
