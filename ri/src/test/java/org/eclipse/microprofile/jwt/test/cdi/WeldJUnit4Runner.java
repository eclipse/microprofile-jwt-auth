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
package org.eclipse.microprofile.jwt.test.cdi;


import java.util.logging.Level;
import java.util.logging.Logger;

import org.jboss.weld.environment.se.Weld;
import org.jboss.weld.environment.se.WeldContainer;
import org.jboss.weld.environment.se.WeldSEProvider;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;

import javax.enterprise.inject.spi.CDI;

/**
 * A simple runner that boots up the Weld Java SE container
 */
public class WeldJUnit4Runner extends BlockJUnit4ClassRunner {

    private final Class<?> klass;
    private final Weld weld;
    private final WeldContainer container;

    /**
     * A little utility method that configures the JDK root and Weld root loggers for the given log level. It also
     * sets the handler associated with the JDK root logger to this level. Typically this is only useful when
     * called with a {@link Level#FINE} level or more verbose.
     * @param level the logger level to set
     */
    public static void enableJDKConsoleLogging(Level level) {
        // Set up the root and org.jboss.weld logger to level and override the ConsoleHandler level to level
        Logger rootLog = Logger.getLogger("");
        rootLog.setLevel( level );
        rootLog.getHandlers()[0].setLevel( level);
        Logger.getLogger("org.jboss.weld").setLevel(Level.ALL);
    }

    public WeldJUnit4Runner(final Class<Object> klass) throws InitializationError {
        super(klass);
        this.klass = klass;
        // Uncomment to enable verbose tracing of CDI
        //enableJDKConsoleLogging(Level.FINEST);
        this.weld = new Weld();
        /* Use this to put the Weld container in development with export of the trace information to the /tmp directory
        this.weld = new Weld().property("org.jboss.weld.development", true)
            .property("org.jboss.weld.probe.exportDataAfterDeployment", "/tmp/");
        */
        this.container = weld.initialize();
        // This is currently needed in order for a class called by the ServiceLoader to be able to access the CDI instance
        WeldSEProvider cdi = new WeldSEProvider();
        CDI.setCDIProvider(cdi);
    }

    @Override
    protected Object createTest() throws Exception {
        final Object test = container.select(klass).get();

        return test;
    }
}
