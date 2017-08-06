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

import org.jboss.arquillian.container.test.spi.client.deployment.ApplicationArchiveProcessor;
import org.jboss.arquillian.core.spi.LoadableExtension;

/**
 * TODO; flesh out the stubs more
 */
public class BaseExtension implements LoadableExtension {
    /**
     * Called to allow for extensions of the Arquillian runtime
     * @param extensionBuilder - extension SPI
     */
    @Override
    public void register(ExtensionBuilder extensionBuilder) {
        Class<? extends ApplicationArchiveProcessor> appClass = getApplicationArchiveProcessor();
        extensionBuilder.service(ApplicationArchiveProcessor.class, appClass);
    }

    /**
     * Override to return your implementation of ApplicationArchiveProcessor
     * @return vendor ApplicationArchiveProcessor implementation
     */
    protected Class<? extends ApplicationArchiveProcessor> getApplicationArchiveProcessor() {
        return BaseWarArchiveProcessor.class;
    }
}
