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

import org.bouncycastle.asn1.x509.X509Name;
import org.glite.security.TestBase;


/**
 * DNTest.java
 *
 * @author  Joni Hahkala
 *
 * Created on September 8, 2003, 8:16 PM
 */
public class DNTest extends TestBase {
    /** test string. */
    static final String TEST_1 = "EMAILADDRESS=johan.doe@foo.bar.net.edu,CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN,C=IT";
    /** test string. */
    static final String TEST_2 = "Email=johan.doe@foo.bar.net.edu,CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN,C=IT";
    /** test string. */
    static final String TEST_3 = "E=johan.doe@foo.bar.net.edu,CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN,C=IT";
    /** test string. */
    static final String TEST_4 = "C=IT,O=INFN,OU=cas server,L=Bologna,CN=cas/aaa-test.cnaf.infn.it,E=johan.doe@foo.bar.net.edu";
    /** test string. */
    static final String TEST_5 = "C=IT,O=INFN,OU=cas server,L=Bologna,CN=cas/aaa-test.cnaf.infn.it,Email=johan.doe@foo.bar.net.edu";
    /** test string. */
    static final String TEST_6 = "C=IT,O=INFN,OU=cas server,L=Bologna,CN=cas/aaa-test.cnaf.infn.it,E=johan.doe@foo.bar.net.edu,CN=proxy";
    /** test string. */
    static final String TEST_7 = "C=IT,O=INFN,OU=cas server,L=Bologna,CN=cas/aaa-test.cnaf.infn.it,E=johan.doe@foo.bar.net.edu,CN=123412341";
    /** test string. */
    static final String TEST_8 = "C=IT,O=INFN,OU=cas server,L=Bologna,CN=cas/aaa-test.cnaf.infn.it,Email=johan.doe@foo.bar.net.edu";

    /** test string. */
    static final String WITHSPACES = "C=US, O=Sun Microsystems, OU=JavaSoft, CN=Duke";
    /** test string. */
    static final String WITHOUTSPACES = "C=US,O=Sun Microsystems,OU=JavaSoft,CN=Duke";
    /** test string. */
    static final String ENDSPACE = "C=US, O=Sun Microsystems, OU=JavaSoft, CN=Duke ";
    

    /**
     * Creates a new DNTest object.
     *
     * @param arg0 DOCUMENT ME!
     */
    public DNTest(final String arg0) {
        super(arg0);
    }

    /**
     * DOCUMENT ME!
     *
     * @param args DOCUMENT ME!
     */
    public static void main(final java.lang.String[] args) {
        junit.textui.TestRunner.run(suite());
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public static Test suite() {
        return new TestSuite(DNTest.class);
    }

    /**
     * DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testGetDNPricipal() {
        //        System.out.println(DNHandler.getDN(new X500Principal(
        // "CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US")).getX500());
        assertEquals(WITHOUTSPACES, DNHandler.getDN(new X509Name(WITHSPACES)).getRFC2253());
    }

    /**
     * DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testGetDNString() {
        assertEquals(DNHandler.getDN("CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US"), DNHandler.getDN("CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US"));
        assertEquals(DNHandler.getDN("C=US, O=Sun Microsystems, OU=JavaSoft, CN=Duke "), DNHandler.getDN("C=US,O=Sun Microsystems,OU=JavaSoft,CN=Duke"));
        assertEquals(TEST_2, DNHandler.getDN(TEST_1).getRFC2253());
        assertEquals(DNHandler.getDN(TEST_2), DNHandler.getDN(TEST_1));
        assertEquals(DNHandler.getDN(TEST_2), DNHandler.getDN(TEST_2));
        assertEquals(DNHandler.getDN(TEST_2), DNHandler.getDN(TEST_3));
        assertEquals(TEST_5, DNHandler.getDN(TEST_4).getRFC2253());
        assertEquals(DNHandler.getDN(TEST_5), DNHandler.getDN(TEST_4));
        assertEquals(DNHandler.getDN(TEST_5), DNHandler.getDN(TEST_5));
    }

    /**
     * DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testWithoutLastDN() {
        assertEquals(DNHandler.getDN(TEST_6).withoutLastCN(true).toString(), TEST_8);
        assertEquals(DNHandler.getDN(TEST_7).withoutLastCN(true).toString(), TEST_8);
        assertEquals(DNHandler.getDN(TEST_6).withoutLastCN(false).toString(), TEST_8);
        assertEquals(DNHandler.getDN(TEST_7).withoutLastCN(false).toString(), TEST_8);

        assertEquals(DNHandler.getDN(TEST_6).withoutLastCN(true), DNHandler.getDN(TEST_8));

        boolean fail = false;

        try {
            DNHandler.getDN("o=test,C=US").withoutLastCN(true);
        } catch (Exception e) {
            fail = true;
        }

        assertTrue(fail);
    }
}
