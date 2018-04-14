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
package issue62;

import java.security.PublicKey;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.inject.Named;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * An example CDI bean that injects the standard MP-JWT config settings
 */
@Named("MPConfig")
@ApplicationScoped
public class AuthConfig {
    @Inject
    private Config config;
    @Inject
    @ConfigProperty(name = "org.eclipse.microprofile.authentication.JWT.verifierPublicKey")
    private String testKey;
    @Inject
    @ConfigProperty(name = "org.eclipse.microprofile.authentication.JWT.verifierPublicKey")
    private PublicKey keyFromPEM;
    @Inject
    @ConfigProperty(name = "org.eclipse.microprofile.authentication.JWT.issuer")
    private String issuer;
    @Inject
    @ConfigProperty(name = "org.eclipse.microprofile.authentication.JWT.issuers")
    private String[] issuers;
    @Inject
    @ConfigProperty(name = "org.eclipse.microprofile.authentication.JWT.clockSkew", defaultValue = "30")
    private int clockSkew;

    public Config getConfig() {
        return config;
    }

    public void setConfig(Config config) {
        this.config = config;
    }

    public String getTestKey() {
        return testKey;
    }

    public PublicKey getKeyFromPEM() {
        return keyFromPEM;
    }

    public String getIssuer() {
        return issuer;
    }

    public String[] getIssuers() {
        return issuers;
    }

    public int getClockSkew() {
        return clockSkew;
    }
}
