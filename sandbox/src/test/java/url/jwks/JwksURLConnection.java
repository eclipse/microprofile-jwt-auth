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
package url.jwks;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.URL;
import java.net.URLConnection;

/**
 * The jwks protocol handler URLConnection implementation.
 */
public class JwksURLConnection extends URLConnection {
    private String path;
    private StringWriter content;

    protected JwksURLConnection(URL url) {
        super(url);
        this.path = url.getPath();
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
        return content.toString();
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return getClass().getResourceAsStream(path);
    }
}
