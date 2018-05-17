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
package org.eclipse.microprofile.jwt.tck.container.servlet;

import java.io.IOException;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.EJB;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.ServletException;
import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.container.ejb.IService;

@ServletSecurity(
    @HttpConstraint(rolesAllowed={"Tester"})
)
@WebServlet("/ServiceServlet/*")
public class ServiceServlet extends HttpServlet {
    @EJB
    private IService serviceEJB;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Principal user = req.getUserPrincipal();
        String pathInfo = req.getPathInfo();
        System.out.printf("pathInfo=%s\n", pathInfo);

        String result = "";
        if(pathInfo.endsWith("/getSubject")) {
            System.out.printf("Calling getSubject\n");
            result = getSubject(resp);
        }
        else {
            System.out.printf("Calling getPrincipalClass\n");
            result = getPrincipalClass(user);
        }
        resp.getWriter().write(result);
    }
    private String getPrincipalClass(Principal user) {
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
    private String getSubject(HttpServletResponse response) throws IOException {
        try {
            Subject subject = (Subject) PolicyContext.getContext("javax.security.auth.Subject.container");
            Set<? extends Principal> principalSet = subject.getPrincipals(JsonWebToken.class);
            if(principalSet.size() > 0) {
                return "subject.getPrincipals(JsonWebToken.class) ok";
            }
            response.sendError(500, "subject.getPrincipals(JsonWebToken.class) == 0");
        }
        catch (PolicyContextException e) {
            e.printStackTrace();
            response.sendError(500, e.getMessage());
        }
        throw new IllegalStateException("subject.getPrincipals(JsonWebToken.class) == 0");
    }
    private String callEJB(HttpServletResponse response) throws IOException {
        return "";
    }
}
