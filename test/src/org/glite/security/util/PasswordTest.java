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

import org.glite.security.TestBase;


/**
 *
 * Testing the Password.
 *
 * @author  Joni Hahkala
 * Created on October 19, 2002, 9:26 PM
 */
public class PasswordTest extends TestBase {
    /** DOCUMENT ME! */
    static Logger logger = Logger.getLogger(PasswordTest.class.getName());

    /** DOCUMENT ME! */
    static String test1 = "test";

    /**
     * Creates a new PasswordTest object.
     *
     * @param arg0 DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public PasswordTest(String arg0) throws Exception {
        super(arg0);
    }

    /**
     * DOCUMENT ME!
     *
     * @param args DOCUMENT ME!
     */
    public static void main(java.lang.String[] args) {
        junit.textui.TestRunner.run(suite());
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public static Test suite() {
        return new TestSuite(PasswordTest.class.getClass());
    }

    /**
     * DOCUMENT ME!
     */
    public void testPassword() {
        Password passwd1 = new Password(test1.toCharArray());

        assertEquals(test1, new String(passwd1.getPassword()));

        Password passwd2 = new Password(null);

        assertEquals(null, passwd2.getPassword());
    }
}
