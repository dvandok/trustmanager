/*
 * Copyright (c) Members of the EGEE Collaboration. 2004. See
 * http://www.eu-egee.org/partners/ for details on the copyright holders.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.glite.security.util;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Vector;

import junit.framework.Test;
import junit.framework.TestSuite;

import org.apache.log4j.Logger;
import org.glite.security.TestBase;

/**
 * Testing the DNHandler. Tests the DNHandler and DNImpl classes.
 * 
 * @author Joni Hahkala Created on August 26, 2003, 10:38 AM
 */
public class CRLCheckerTest extends TestBase {
    /** Test logger. */
    static final Logger LOGGER = Logger.getLogger(CRLCheckerTest.class.getName());

    /**
     * Creates a new instance of DNHandlerTest
     * 
     * @param arg0 not used.
     */
    public CRLCheckerTest(String arg0) {
        super(arg0);
    }

    /**
     * Support running this test class separately.
     * 
     * @param args not used.
     */
    public static void main(java.lang.String[] args) {
        junit.textui.TestRunner.run(suite());
    }

    /**
     * Base test suite.
     * 
     * @return The test framework.
     */
    public static Test suite() {
        return new TestSuite(CRLCheckerTest.class);
    }

    /**
     * Test the kek crl with extension.
     */
    @SuppressWarnings("boxing")
    public void testKEKCRL() throws CertificateException, IOException, ClassNotFoundException, IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException {
        FileCertReader reader = new FileCertReader();

        @SuppressWarnings("rawtypes")
		Vector caVector = reader.readCerts(m_utilJavaRoot + "/test/input/kek.0");
        @SuppressWarnings("unchecked")
		X509Certificate caCert = (X509Certificate) caVector.toArray(new X509Certificate[] {})[0];

        @SuppressWarnings("unused")
		FileCRLChecker crlChecker = new FileCRLChecker(caCert, m_utilJavaRoot + "/test/input/kek", 0, null);
        
//        crlChecker.check(caCert);
        
        Class<?> c = Class.forName("org.glite.security.util.FileCRLChecker");
        
        crlChecker = (FileCRLChecker)c.getConstructor(X509Certificate.class, String.class, int.class, CaseInsensitiveProperties.class).newInstance(caCert, m_utilJavaRoot + "/test/input/kek", 0, null);
        
    }
    /**
     * Test the kek crl with extension.
     */
//    public void testExtCRL() throws CertificateException, IOException, ClassNotFoundException, IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException {
//        FileCertReader reader = new FileCertReader();
//
//        Vector caVector = reader.readCerts("/etc/grid-security/certificates/a317c467.0");
//        X509Certificate caCert = (X509Certificate) caVector.toArray(new X509Certificate[] {})[0];
//
//        FileCRLChecker crlChecker = new FileCRLChecker(caCert, "/etc/grid-security/certificates/a317c467", 0, null);
//        
//        crlChecker.check(caCert);
//        
//        Class c = Class.forName("org.glite.security.util.FileCRLChecker");
//        
//        crlChecker = (FileCRLChecker)c.getConstructor(X509Certificate.class, String.class, int.class, CaseInsensitiveProperties.class).newInstance(caCert, m_utilJavaRoot + "/test/input/kek", 0, null);
//        
//    }
}
