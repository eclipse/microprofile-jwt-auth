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

import java.net.URL;
import java.net.URLClassLoader;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ServiceLoader;

import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.spi.ConfigBuilder;
import org.eclipse.microprofile.config.spi.ConfigSource;
import org.eclipse.microprofile.config.spi.Converter;

/**
 * The Weld/JavaSE ConfigBuilder implementation. It configures a {@link DefaultConfig} instance.
 */
public class DefaultConfigBuilder implements ConfigBuilder {
    @Inject
    private BeanManager beanManager;
    private DefaultConfig config = new DefaultConfig();
    private ClassLoader loader;

    public DefaultConfigBuilder() {
        loader = AccessController.doPrivileged((PrivilegedAction<ClassLoader>) () -> Thread.currentThread().getContextClassLoader());
    }
    @Override
    public ConfigBuilder addDefaultSources() {
        config.loadStandardSources(loader);
        return this;
    }

    @Override
    public ConfigBuilder addDiscoveredSources() {
        boolean debugClassLoader = Boolean.getBoolean("config.seimpl.debugClassLoader");
        if(debugClassLoader) {
            System.out.printf("ClassLoader: %s\n", loader);
            if (loader instanceof URLClassLoader) {
                URLClassLoader urlClassLoader = (URLClassLoader) loader;
                URL[] urls = urlClassLoader.getURLs();
                for (URL url : urls) {
                    System.out.printf("\t: %s\n", url);
                }
            }
        }
        ServiceLoader<ConfigSource> sources = ServiceLoader.load(ConfigSource.class, loader);
        int count = 0;
        for(ConfigSource cs : sources) {
            config.addConfigSource(cs);
            count ++;
        }
        System.out.printf("Discovered %d additional ConfigSource\n", count);
        return this;
    }

    @Override
    public ConfigBuilder addDiscoveredConverters() {
        ServiceLoader<Converter> converters = ServiceLoader.load(Converter.class, loader);
        converters.forEach(converter -> config.addConverter(converter));
        return this;
    }

    @Override
    public ConfigBuilder forClassLoader(ClassLoader loader) {
        this.loader = loader;
        return this;
    }

    @Override
    public ConfigBuilder withSources(ConfigSource... sources) {
        for(ConfigSource cs : sources) {
            config.addConfigSource(cs);
        }
        return this;
    }

    @Override
    public ConfigBuilder withConverters(Converter<?>[] converters) {
        for(Converter converter : converters) {
            config.addConverter(converter);
        }
        return this;
    }

    @Override
    public Config build() {
        return config;
    }

    @Override
    public <T> ConfigBuilder withConverter(Class<T> type, int priority, Converter<T> converter) {
        config.addConverter(converter);
        return this;
    }
}
