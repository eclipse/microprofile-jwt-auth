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
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Optional;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.DeploymentException;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.inject.Inject;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import config.seimpl.DefaultConfig;

/**
 * A CDI producer method bean that handles injection of @ConfigProperty annotated values.
 */
@ApplicationScoped
public class ConfigPropertyProducer {
    @Inject
    private Config appConfig;
    private DefaultConfig config;

    @PostConstruct
    void init() {
        config = (DefaultConfig) appConfig;
    }

    @Produces
    @ConfigProperty
    @Dependent
    private Object produceConfigProperty(InjectionPoint injectionPoint) {
        System.out.printf("produceConfigProperty: %s\n", injectionPoint);
        boolean isOptional = injectionPoint.getAnnotated().getBaseType().getTypeName().startsWith("java.util.Optional");
        Class<?> toType = unwrapType(injectionPoint.getAnnotated().getBaseType());

        Object value = getValue(injectionPoint, toType, isOptional);
        return isOptional ? Optional.ofNullable(value) : value;
    }

    private <T> T getValue(InjectionPoint injectionPoint, Class<T> target, boolean isOptional) {
        String name = getName(injectionPoint);
        if (name == null || name.isEmpty() || this.config == null) {
            return null;
        }

        Optional<T> configValue = this.config.getOptionalValue(name, target);
        if(!configValue.isPresent()) {
            // Check for a default value
            String defaultValue = getDefaultValue(injectionPoint);
            if(defaultValue != null && !defaultValue.contentEquals(ConfigProperty.UNCONFIGURED_VALUE)) {
                configValue = this.config.tryConvertValue(defaultValue, target);
            }
        }
        if(!isOptional && !configValue.isPresent()) {
            System.err.printf("Failed to find ConfigProperty for: %s\n", injectionPoint);
            throw new DeploymentException(String.format("%s has no configured value", name));
        }
        return configValue.orElse(null);
    }

    private String getName(InjectionPoint injectionPoint) {
        for (Annotation qualifier : injectionPoint.getQualifiers()) {
            if (qualifier.annotationType().equals(ConfigProperty.class)) {
                // Check for a non-default value
                String name = ((ConfigProperty) qualifier).name();
                if(name.length() == 0) {
                    //
                    name = injectionPoint.getBean().getBeanClass().getTypeName() + "." + injectionPoint.getMember().getName();
                }
                return name;
            }
        }
        return null;
    }
    private String getDefaultValue(InjectionPoint injectionPoint) {
        String defaultValue = null;
        for (Annotation qualifier : injectionPoint.getQualifiers()) {
            if (qualifier.annotationType().equals(ConfigProperty.class)) {
                // Check for a non-default value
                defaultValue = ((ConfigProperty) qualifier).defaultValue();
                if(defaultValue.length() == 0) {
                    defaultValue = null;
                }
                break;
            }
        }
        return defaultValue;
    }

    @SuppressWarnings("unchecked")
    private <T> Class<T> unwrapType(Type type) {
        if (type instanceof ParameterizedType) {
            type = ((ParameterizedType) type).getActualTypeArguments()[0];
        }
        return (Class<T>) type;
    }
}
