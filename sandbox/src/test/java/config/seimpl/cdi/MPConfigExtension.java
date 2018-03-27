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


import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Set;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AfterBeanDiscovery;
import javax.enterprise.inject.spi.AfterTypeDiscovery;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.BeforeBeanDiscovery;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.ProcessAnnotatedType;
import javax.enterprise.inject.spi.ProcessBean;
import javax.enterprise.inject.spi.ProcessBeanAttributes;
import javax.enterprise.inject.spi.ProcessInjectionPoint;
import javax.enterprise.inject.spi.ProcessInjectionTarget;
import javax.enterprise.inject.spi.ProcessProducer;

import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * The CDI Extension that tracks the @ConfigProperty injection points.
 */
public class MPConfigExtension implements Extension {
    private Set<Type> configPropertyTypes = new HashSet<>();

    void afterTypeDiscovery(@Observes AfterTypeDiscovery event) {
        System.out.printf("afterTypeDiscovery, configPropertyTypes=%s\n", configPropertyTypes);
    }
    void afterBeanDiscovery(@Observes AfterBeanDiscovery event, BeanManager manager) {
        if(configPropertyTypes.size() == 0) {
            configPropertyTypes.add(String.class);
        }
        System.out.printf("afterBeanDiscovery, configPropertyTypes=%s\n", configPropertyTypes);
    }

    void doProcessAnnotatedType(@Observes ProcessAnnotatedType pat) {
        System.out.printf("pat: %s\n", pat.getAnnotatedType());
    }

    /**
     * Collect the types of all injection points annotated with @ConfigProperty.
     * @param pip - the injection point event information
     */
    void processConfigPropertyInjections(@Observes ProcessInjectionPoint pip) {
        System.out.printf("pip: %s\n", pip.getInjectionPoint());
        InjectionPoint ip = pip.getInjectionPoint();
        if (ip.getAnnotated().isAnnotationPresent(ConfigProperty.class)) {
            configPropertyTypes.add(ip.getType());
            System.out.printf("+++ Added ConfigProperty target type: %s\n", ip.getType());
        }
    }
    void doProcessProducers(@Observes ProcessProducer pp) {
        System.out.printf("pp: %s, %s\n", pp.getAnnotatedMember(), pp.getProducer());
    }
    void doProcessBeanAttributes(@Observes ProcessBeanAttributes pba) {
        System.out.printf("pab: %s\n", pba.getAnnotated());
        if (pba.getAnnotated().isAnnotationPresent(ConfigProperty.class)) {
            System.out.printf("\t+++ has ConfigProperty annotation\n");
            //pba.setBeanAttributes(new ConverterBeanAttribute(pba.getBeanAttributes(), types));
        }
    }
    void doProcessBean(@Observes ProcessBean pb) {
        System.out.printf("pb: %s, class:%s, types:%s\n", pb.getAnnotated(), pb.getBean().getBeanClass(), pb.getBean().getTypes());
        if (pb.getAnnotated().isAnnotationPresent(ConfigProperty.class)) {
            System.out.printf("\t+++ has ConfigProperty annotation\n");
            //pba.setBeanAttributes(new ConverterBeanAttribute(pba.getBeanAttributes(), types));
        }
    }
    void findNeededConfigPropertyProducers(@Observes ProcessInjectionTarget<ConfigProperty> pit) {
        System.out.printf("ConfigPropertyTarget: %s", pit.getInjectionTarget());
    }

    /**
     * Replace our {@linkplain ConfigPropertyProducer#produceConfigProperty(InjectionPoint)} BeanAttributes with
     * {@linkplain ConfigPropertyBeanAttribute} to properly reflect all of the type locations the producer method applies to.
     * @see ConfigPropertyBeanAttribute
     * @param pba
     */
    public void addTypeToConfigProperty(@Observes ProcessBeanAttributes<Object> pba) {
        if (pba.getAnnotated().isAnnotationPresent(ConfigProperty.class)) {
            System.out.printf("addTypeToConfigProperty: %s", pba);
            pba.setBeanAttributes(new ConfigPropertyBeanAttribute(pba.getBeanAttributes(), configPropertyTypes));
        }
    }

    public void addConfigPropertyProduer(@Observes BeforeBeanDiscovery bbd, BeanManager beanManager) {
        System.out.printf("MPConfigExtension, added ConfigPropertyProduer\n");
        //bbd.addAnnotatedType(beanManager.createAnnotatedType(ConfigProducer.class));
        //bbd.addAnnotatedType(beanManager.createAnnotatedType(ConfigPropertyProducer.class));
    }
}
