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
package issue62;

import java.util.Arrays;
import java.util.HashSet;

import javax.inject.Inject;

import cdi.WeldJUnit4Runner;
import org.eclipse.microprofile.config.Config;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Test injection of MP-JWT config values
 */
@RunWith(WeldJUnit4Runner.class)
public class AuthConfigTest {

    @Inject
    private AuthConfig authConfig;

    @Test
    public void testConfigPropertyInjection() {
        Config config = authConfig.getConfig();
        System.out.println(config);
        Assert.assertEquals("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlivFI8qB4D0y2jy0CfEqFyy46R0o7S8TKpsx5xbHKoU1"
                            +"VWg6QkQm+ntyIv1p4kE1sPEQO73+HY8+Bzs75XwRTYL1BmR1w8J5hmjVWjc6R2BTBGAYRPFRhor3kpM6ni2SPmNNhurEAHw7Ta"
                            +"qszP5eUF/F9+KEBWkwVta+PZ37bwqSE4sCb1soZFrVz/UT/LF4tYpuVYt3YbqToZ3pZOZ9AX2o1GCG3xwOjkc4x0W7ezbQZdC"
                            +"9iftPxVHR8irOijJRRjcPDtA6vPKpzLl6CyYnsIYPd99ltwxTHjr3npfv/3Lw50bAkbT4HeLFxTx4flEoZLKO/g0bAoV2uqBh"
                            +"kA9xnQIDAQAB", authConfig.getTestKey());
        Assert.assertEquals(15, authConfig.getClockSkew());
        Assert.assertEquals("https://mpconference.com", authConfig.getIssuer());
        String[] issuers = authConfig.getIssuers();
        HashSet<String> issuersSet = new HashSet<>(Arrays.asList(issuers));
        Assert.assertTrue("https://www.mpconference.com", issuersSet.contains("https://www.mpconference.com"));
        Assert.assertTrue("https://mpconference.com", issuersSet.contains("https://mpconference.com"));
    }

    @Test
    public void testAuthDefinition() {
        // TODO?
    }
}
