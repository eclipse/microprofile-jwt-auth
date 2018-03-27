/*
 *  Copyright (c) 2011-2017 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  Contributors:
 */
package config.seimpl;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.eclipse.microprofile.config.spi.ConfigSource;

/**
 * A default implementation of a ConfigSource that loads configuration from /META-INF/microprofile-config.properties
 */
public class DefaultMPConfigSource implements ConfigSource {
    private URL mpcURL;
    private HashMap<String, String> properties = new HashMap<>();

    DefaultMPConfigSource(ClassLoader loader) throws IOException {
        mpcURL = loader.getResource("META-INF/microprofile-config.properties");
        Properties tmp = new Properties();
        if(mpcURL != null) {
            tmp.load(mpcURL.openStream());
        }
        tmp.forEach((key, value) -> properties.put((String) key, (String) value));
    }

    @Override
    public int getOrdinal() {
        return 100;
    }
    @Override
    public Map<String, String> getProperties() {
        return properties;
    }

    @Override
    public String getValue(String propertyName) {
        String propertyVaue = properties.get(propertyName);
        return propertyVaue;
    }

    @Override
    public String getName() {
        return mpcURL != null ? mpcURL.toExternalForm() : "NONE";
    }
}
