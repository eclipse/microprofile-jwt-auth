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
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.SortedSet;
import java.util.concurrent.ConcurrentSkipListSet;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Vetoed;

import config.seimpl.converters.StringArrayConverter;
import org.eclipse.microprofile.config.Config;
import config.seimpl.converters.BooleanConverter;
import config.seimpl.converters.ByteConverter;
import config.seimpl.converters.CharacterConverter;
import config.seimpl.converters.DoubleConverter;
import config.seimpl.converters.DurationConverter;
import config.seimpl.converters.FloatConverter;
import config.seimpl.converters.IntegerConverter;
import config.seimpl.converters.LocalDateTimeConverter;
import config.seimpl.converters.LongConverter;
import config.seimpl.converters.ShortConverter;
import org.eclipse.microprofile.config.spi.ConfigSource;
import org.eclipse.microprofile.config.spi.Converter;

/**
 * Created by starksm on 6/1/17.
 */
@Vetoed
public class DefaultConfig implements Config {
    private static SystemEnvConfigSource systemEnvCS = new SystemEnvConfigSource();
    private static SystemPropertyConfigSource systemPropertyCS = new SystemPropertyConfigSource();

    /**
     * The list of ConfigSource objects ordered by their ordinal value
     */
    private SortedSet<ConfigSource> sources = new ConcurrentSkipListSet<>(Comparator.comparing(ConfigSource::getOrdinal));
    private HashMap<Type, Converter> converters = new HashMap<>();

    DefaultConfig() {
        loadStandardConverters();
    }
    DefaultConfig(List<ConfigSource> sources) {
        this.sources.addAll(sources);
        loadStandardConverters();
    }

    public void loadStandardSources(ClassLoader loader) {
        if(loader == null) {
            loader = getClass().getClassLoader();
        }
        sources.add(systemPropertyCS);
        System.out.printf("Added System property ConfigSource\n");
        sources.add(systemEnvCS);
        System.out.printf("Added System environment ConfigSource\n");
        try {
            sources.add(new DefaultMPConfigSource(loader));
            System.out.printf("Added META-INF/microprofile-config.properties ConfigSource\n");
        }
        catch (IOException e) {
            // Ignore
        }
    }

    public void loadStandardConverters() {
        converters.put(Boolean.class, new BooleanConverter());
        converters.put(boolean.class, new BooleanConverter());
        converters.put(Character.class, new CharacterConverter());
        converters.put(char.class, new CharacterConverter());
        converters.put(Byte.class, new ByteConverter());
        converters.put(byte.class, new ByteConverter());
        converters.put(Short.class, new ShortConverter());
        converters.put(short.class, new ShortConverter());
        converters.put(Integer.class, new IntegerConverter());
        converters.put(int.class, new IntegerConverter());
        converters.put(Long.class, new LongConverter());
        converters.put(long.class, new LongConverter());
        converters.put(Float.class, new FloatConverter());
        converters.put(float.class, new FloatConverter());
        converters.put(Double.class, new DoubleConverter());
        converters.put(double.class, new DoubleConverter());
        converters.put(Duration.class, new DurationConverter());
        converters.put(LocalDateTime.class, new LocalDateTimeConverter());
        converters.put(String[].class, new StringArrayConverter());
    }

    /**
     * Use the {@link Converter}s registered with the config to convert a String value to a target property type.
     * @param svalue - the string value representation of the property
     * @param propertyType - the desired Java type of the property
     * @return the converted value
     * @throws TypeNotPresentException if there is no registered Converter
     */
    public <T> T convertValue(String svalue, Class<T> propertyType) {
        T value = null;
        if(propertyType.isAssignableFrom(String.class)) {
            value = propertyType.cast(svalue);
        }
        else {
            Converter<T> converter = converters.get(propertyType);
            if(converter != null) {
                value = converter.convert(svalue);
            }
            else {
                System.err.printf("Failed to find Converter for type: %s\n", propertyType);
                throw new TypeNotPresentException(propertyType.getTypeName(), null);
            }
        }
        return value;
    }

    /**
     * Use the {@link Converter}s registered with the config to try to convert a String value to a target property type.
     * @param svalue - the string value representation of the property
     * @param propertyType - the desired Java type of the property
     * @return the converted value if a matching converter is found, Optional.empty() otherwise
     */
    public <T> Optional<T> tryConvertValue(String svalue, Class<T> propertyType) {
        Optional<T> value = Optional.empty();
        if(propertyType.isAssignableFrom(String.class)) {
            value = Optional.of((T)svalue);
        }
        else {
            Converter<T> converter = converters.get(propertyType);
            if(converter != null) {
                value = Optional.of(converter.convert(svalue));
            }
            else {
                System.err.printf("Failed to find Converter for type: %s\n", propertyType);
            }
        }
        return value;
    }

    /**
     * Add a new ConfigSource. This will be added to the existing sources based on the {@link ConfigSource#getOrdinal()} value.
     * @param cs the ConfigSource to add
     * @return true if the ConfigSource was added, false otherwise
     */
    public boolean addConfigSource(ConfigSource cs) {
        return sources.add(cs);
    }
    public void addConverter(Converter converter) {
        // Determine the target type of the converter
        Type[] genericInterfaces = converter.getClass().getGenericInterfaces();
        for(Type type : genericInterfaces) {
            if(type instanceof ParameterizedType) {
                ParameterizedType ptype = (ParameterizedType) type;
                if(ptype.getRawType().equals(Converter.class)) {
                    Type actualType = ptype.getActualTypeArguments()[0];
                    converters.put(actualType, converter);
                    System.out.printf("+++ Added converter(%s) for type: %s\n", converter, actualType);
                }
            }
        }
    }

    @Override
    public <T> T getValue(String propertyName, Class<T> propertyType) {
        T value = getOptionalValue(propertyName, propertyType).orElse(null);
        return value;
    }

    @Override
    public <T> Optional<T> getOptionalValue(String propertyName, Class<T> propertyType) {
        Optional<T> value = Optional.empty();
        for (ConfigSource cs : sources) {
            String svalue = cs.getValue(propertyName);
            if(svalue == null) {
                value = Optional.empty();
            }
            else if(propertyType.isAssignableFrom(String.class)) {
                value = Optional.of(propertyType.cast(svalue));
                break;
            }
            else {
                Converter<T> converter = converters.get(propertyType);
                if(converter != null) {
                    value = Optional.of(converter.convert(svalue));
                }
                else {
                    System.err.printf("Failed to find Converter for: %s of type: %s\n", propertyName, propertyType);
                }
                break;
            }
        }
        return value;
    }

    @Override
    public Iterable<String> getPropertyNames() {
        return null;
    }

    @Override
    public Iterable<ConfigSource> getConfigSources() {
        return sources;
    }
}
