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

package config.seimpl.cdi;

import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.Set;

import javax.enterprise.inject.spi.BeanAttributes;

/**
 * Implementation of {@link BeanAttributes} SPI to decorate an existing <pre>BeanAttributes</pre>
 * by replacing its type set with the full set of @ConfigProperty injection target site types. Based on the converter example
 * in the CDI-Sandbox(https://github.com/starksm64/CDI-Sandbox.git)
 * @author Antoine Sabot-Durand
 * @author Scott Stark
 */
public class ConfigPropertyBeanAttribute implements BeanAttributes<Object> {
    /**
     * Decorate the ConfigPropertyProducer BeanAttributes to set the types the producer applies to. This set is collected
     * from all injection points annotated with @ConfigProperty.
     *
     * @see MPConfigExtension#processConfigPropertyInjections
     * @see ConfigPropertyProducer#produceConfigProperty(javax.enterprise.inject.spi.InjectionPoint)
     *
     * @param delegate - the original producer method BeanAttributes
     * @param types - the full set of @ConfigProperty injection point types
     */
    public ConfigPropertyBeanAttribute(BeanAttributes<Object> delegate, Set<Type> types) {
        this.delegate = delegate;
        this.types = types;
        if(this.types.size() == 0) {
            this.types.add(String.class);
        }
    }

    @Override
    public Set<Type> getTypes() {
        return types;
    }

    @Override
    public Set<Annotation> getQualifiers() {
        return delegate.getQualifiers();
    }

    @Override
    public Class<? extends Annotation> getScope() {
        return delegate.getScope();
    }

    @Override
    public String getName() {
        return delegate.getName();
    }

    @Override
    public Set<Class<? extends Annotation>> getStereotypes() {
        return delegate.getStereotypes();
    }

    @Override
    public boolean isAlternative() {
        return delegate.isAlternative();
    }

    private BeanAttributes<Object> delegate;

    private Set<Type> types;

}
