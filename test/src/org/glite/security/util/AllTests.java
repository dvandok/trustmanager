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

import junit.framework.Test;
import junit.framework.TestSuite;

import org.apache.log4j.Logger;

import org.glite.security.SecurityContextTest;
import org.glite.security.TestBase;
import org.glite.security.util.namespace.DNCheckerTest;
import org.glite.security.util.proxy.ProxyCertificateGeneratorTest;
import org.glite.security.util.proxy.ProxyRestrictionTest;


/**
 * AllTests.java
 *
 * @author  Joni Hahkala <joni.hahkala@cern.ch>
 *
 * Created on September 20, 2002, 6:24 PM
 */
public class AllTests extends org.glite.security.AllTests {
    /** DOCUMENT ME! */
    static Logger logger = Logger.getLogger(AllTests.class.getPackage().getName());

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public static Test suite() {
        TestBase.initEnv();

        TestSuite suite = new TestSuite("All Security Utility tests");

        //$JUnit-BEGIN$
        suite.addTest(new TestSuite(SecurityContextTest.class));

        suite.addTest(new TestSuite(CaseInsensitivePropertiesTest.class));
        suite.addTest(new TestSuite(DNHandlerTest.class));
        suite.addTest(new TestSuite(DNTest.class));
        suite.addTest(new TestSuite(FileCertReaderTest.class));
        suite.addTest(new TestSuite(IPAddressComparatorTest.class));
        suite.addTest(new TestSuite(PasswordTest.class));
        suite.addTest(new TestSuite(PrivateKeyReaderTest.class));
        suite.addTest(new TestSuite(CertUtilTest.class));
        suite.addTest(new TestSuite(CRLCheckerTest.class));
        suite.addTest(new TestSuite(TrustStorageTest.class));
        suite.addTest(HostNameCheckerTest.suite());
        
        suite.addTest(new TestSuite(DNCheckerTest.class));

        suite.addTest(new TestSuite(ProxyCertificateGeneratorTest.class));
        suite.addTest(new TestSuite(ProxyRestrictionTest.class));

        //$JUnit-END$
        return suite;
    }
}
