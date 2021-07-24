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
package org.eclipse.microprofile.jwt.tck.arquillian;

import java.util.logging.Logger;

import org.jboss.arquillian.container.test.spi.client.deployment.ApplicationArchiveProcessor;
import org.jboss.arquillian.test.spi.TestClass;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.spec.WebArchive;

/**
 * A base ApplicationArchiveProcessor for illustrating use and simplifying common implementations. TODO: flesh out the
 * stubs more
 */
public abstract class BaseWarArchiveProcessor implements ApplicationArchiveProcessor {
    private static Logger log = Logger.getLogger(BaseWarArchiveProcessor.class.getName());

    @Override
    public void process(Archive<?> appArchive, TestClass testClass) {
        if (!(appArchive instanceof WebArchive)) {
            return;
        }
        log.info("Preparing archive: " + appArchive);
        WebArchive war = WebArchive.class.cast(appArchive);
        // Add WEB-INF resources
        String[] webInfRes = getWebInfResources();
        for (String resName : webInfRes) {
            war.addAsWebInfResource(resName);
        }

        // Add WEB-INF/lib libraries
        String[] artifactNames = getWebInfLibArtifacts();
        // TODO; use shrinkwrap resolvers
        for (String mvnArtifact : artifactNames) {
            // Resolve this artifact...
        }
    }

    /**
     * Called to get names of WEB-INF resources
     * 
     * @return names of classpath resources to add to the WEB-INF directory, empty for none
     */
    protected String[] getWebInfResources() {
        String[] empty = {};
        return empty;
    }

    /**
     * groupId:artifactId:version dependencies to include in WEB-INF/lib directory
     * 
     * @return names of mvn dependencies to include, empty for none
     */
    protected String[] getWebInfLibArtifacts() {
        String[] empty = {};
        return empty;
    }
}
