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

package org.glite.security;

import junit.framework.Test;
import junit.framework.TestSuite;


/**
 * DOCUMENT ME!
 *
 * @author Joni Hahkala <joni.hahkala@cern.ch>
 */
public class AllTests extends TestSuite {
    /**
     * DOCUMENT ME!
     *
     * @param args DOCUMENT ME!
     */
    public static void main(String[] args) {
        junit.textui.TestRunner.run(suite());
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public static Test suite() {
        TestBase.initEnv();

        TestSuite suite = new TestSuite("All Security Utility tests");

        //$JUnit-BEGIN$
        suite.addTest(org.glite.security.util.AllTests.suite());
        suite.addTest(org.glite.security.trustmanager.ContextWrapperFuncTest.suite());
        suite.addTest(org.glite.security.trustmanager.ContextWrapperFuncOpensslTest.suite());
        suite.addTest(org.glite.security.trustmanager.ProxyCertPathValidatorTest.suite());
        suite.addTest(org.glite.security.trustmanager.OpensslCertPathValidatorTest.suite());
        suite.addTest(new TestSuite(org.glite.security.trustmanager.UpdatingKeyManagerTest.class));
//        suite.addTest(org.glite.security.voms.AllTests.suite());
        suite.addTest(new TestSuite(SecurityContextTest.class));

        //$JUnit-END$
        return suite;
    }
}
