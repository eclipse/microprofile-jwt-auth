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
package org.eclipse.microprofile.jwt.tck.container.ejb;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import javax.annotation.Resource;
import javax.annotation.security.RolesAllowed;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;

import org.eclipse.microprofile.jwt.JsonWebToken;

@Stateless
public class ServiceEJB implements IService {

    @Resource
    private SessionContext ctx;

    @RolesAllowed("Echoer")
    public String echo(String input) {
        Principal user = ctx.getCallerPrincipal();
        return String.format("ServiceEJB, input=%s, user=%s", input, user.getName());
    }

    @RolesAllowed("Tester")
    public String getPrincipalClass() {
        Principal user = ctx.getCallerPrincipal();
        System.out.printf("ServiceEJB.getPrincipalClass, user=%s, class=%s\n", user.getName(), user.getClass());
        HashSet<Class> interfaces = new HashSet<>();
        Class current = user.getClass();
        while(current.equals(Object.class) == false) {
            Class[] tmp = current.getInterfaces();
            for(Class c : tmp) {
                interfaces.add(c);
            }
            current = current.getSuperclass();
        }
        StringBuilder tmp = new StringBuilder();
        for(Class iface : interfaces) {
            tmp.append(iface.getTypeName());
            tmp.append(',');
        }
        tmp.setLength(tmp.length()-1);
        return tmp.toString();
    }
    @RolesAllowed("Tester")
    public String getSubjectClass() throws Exception {
        Subject subject = (Subject) PolicyContext.getContext("javax.security.auth.Subject.container");
        System.out.printf("ServiceEJB.getSubjectClass, subject=%s\n", subject);
        Set<? extends Principal> principalSet = subject.getPrincipals(JsonWebToken.class);
        if (principalSet.size() > 0) {
            return "subject.getPrincipals(JsonWebToken.class) ok";
        }
        throw new IllegalStateException("subject.getPrincipals(JsonWebToken.class) == 0");
    }
}
