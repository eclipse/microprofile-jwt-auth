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
package url.pemjwks;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

import org.eclipse.microprofile.jwt.tck.util.TokenUtils;

/**
 * The pemjwks protocol URLConnection implementation
 */
public class PemJwksURLConnection extends URLConnection {
    private String path;
    private String kid;
    private StringWriter content;

    protected PemJwksURLConnection(URL url) {
        super(url);
        this.path = url.getPath();
        // Look for kid=xxx
        String query = url.getQuery();
        if(query != null) {
            String[] parts = query.split("=");
            kid = parts[1];
        }
        else {
            // Some random kid
            kid = Long.toHexString(Double.doubleToLongBits(Math.random()));
        }
    }

    @Override
    public void connect() throws IOException {
        InputStream is = getInputStream();
        if(is == null) {
            throw new FileNotFoundException(path);
        }
        content = new StringWriter();
        try(BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line = reader.readLine();
            while(line != null) {
                content.write(line);
                content.write('\n');
                line = reader.readLine();
            }
        }
    }

    @Override
    public String getContentType() {
        return "application/json";
    }

    @Override
    public Object getContent() throws IOException {
        if(content == null) {
            connect();
        }
        //
        RSAPublicKey publicKey;
        try {
            publicKey = (RSAPublicKey) TokenUtils.decodePublicKey(content.toString());
        }
        catch (Exception e) {
            throw new IOException(e);
        }
        /*
            "keys": [
                {
                    "kty": "RSA",
                    "e": "AQAB",
                    "use": "sig",
                    "kid": "jwk-test",
                    "alg": "RS256",
                    "n": "uGU_nmjYC7cK...
                }
            ]
         */
        JsonObjectBuilder jwksBuilder = Json.createObjectBuilder();
        JsonObjectBuilder keyBuilder = Json.createObjectBuilder();
        BigInteger nBI = publicKey.getModulus();
        byte[] nbytes = nBI.toByteArray();
        if ((nBI.bitLength() % 8 == 0) && nbytes[0] == 0 && nbytes.length > 1) {
            byte[] tmp = new byte[nbytes.length-1];
            System.arraycopy(nbytes, 1, tmp, 0, tmp.length);
            nbytes = tmp;
        }
        String n = new String(Base64.getUrlEncoder().withoutPadding().encode(nbytes));
        BigInteger eBI = publicKey.getPublicExponent();
        byte[] ebytes = eBI.toByteArray();
        if ((eBI.bitLength() % 8 == 0) && ebytes[0] == 0 && ebytes.length > 1) {
            byte[] tmp = new byte[nbytes.length-1];
            System.arraycopy(nbytes, 1, tmp, 0, tmp.length);
            nbytes = tmp;
        }
        String e = new String(Base64.getUrlEncoder().withoutPadding().encode(ebytes));

        keyBuilder
            .add("kty", "RSA")
            .add("use", "sig")
            .add("alg", "RS256")
            .add("kid", kid)
            .add("e", e)
            .add("n", n);
        JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
        arrayBuilder.add(keyBuilder);
        jwksBuilder.add("keys", arrayBuilder);
        JsonObject jwks = jwksBuilder.build();
        return jwks.toString();
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return getClass().getResourceAsStream(path);
    }
}
