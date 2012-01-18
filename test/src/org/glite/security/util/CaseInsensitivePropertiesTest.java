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

import java.util.Properties;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;


/**
 *
 * Testing CaseInsensitiveProperties
 * 
 * @author  Joni Hahkala
 *
 * Created on September 30, 2002, 3:04 PM
 */
public class CaseInsensitivePropertiesTest extends TestCase {
    /** Creates a new instance of CaseInsensitivePropertiesTest */
    public CaseInsensitivePropertiesTest(String arg0) throws Exception {
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
        return new TestSuite(CaseInsensitivePropertiesTest.class);
    }

    //tests constructor and most of get/set property and loadProperties
    /**
     * DOCUMENT ME!
     */
    public void testConstructor1() {
        Properties defaults = new java.util.Properties();
        defaults.setProperty("BIG", "BIG default");
        defaults.setProperty("small", "small default");
        defaults.setProperty("MiX", "MiX default");

        CaseInsensitiveProperties defTest = new CaseInsensitiveProperties(defaults);

        assertEquals("BIG default", defTest.getProperty("BIG"));
        assertEquals("small default", defTest.getProperty("small"));
        assertEquals("MiX default", defTest.getProperty("MiX"));

        Properties interProps = new Properties(defaults);

        defTest = new CaseInsensitiveProperties(interProps);

        assertTrue(defTest.getProperty("test") == null);
        assertEquals("BIG default", defTest.getProperty("BIG"));
        assertEquals("small default", defTest.getProperty("small"));
        assertEquals("MiX default", defTest.getProperty("MiX"));

        defTest.setProperty("big", "big new");
        defTest.setProperty("small", "small new");
        defTest.setProperty("mix", "mix new");

        assertEquals("big new", defTest.getProperty("BIG"));
        assertEquals("small new", defTest.getProperty("small"));
        assertEquals("mix new", defTest.getProperty("MiX"));

        assertEquals("big new", defTest.getProperty("big"));
        assertEquals("small new", defTest.getProperty("SMALL"));
        assertEquals("mix new", defTest.getProperty("mIx"));

        defTest.setProperty("BIG", "big new2");
        defTest.setProperty("SMALL", "small new2");
        defTest.setProperty("MIX", "mix new2");

        assertEquals("big new2", defTest.getProperty("BIG"));
        assertEquals("small new2", defTest.getProperty("small"));
        assertEquals("mix new2", defTest.getProperty("MiX"));

        assertEquals("big new2", defTest.getProperty("big"));
        assertEquals("small new2", defTest.getProperty("SMALL"));
        assertEquals("mix new2", defTest.getProperty("mIx"));

        boolean success = false;

        try {
            defTest.setProperty("big", null);
        } catch (NullPointerException e) {
            success = true;
        }

        assertTrue(success);

        defTest = new CaseInsensitiveProperties(interProps);

        defTest.setProperty("Big", "BIG set");
        defTest.setProperty("Small", "small set");
        defTest.setProperty("Mix", "MiX set");

        assertTrue(defTest.getProperty("test") == null);
        assertEquals("BIG set", defTest.getProperty("BIG"));
        assertEquals("small set", defTest.getProperty("small"));
        assertEquals("MiX set", defTest.getProperty("MiX"));

        defTest.setProperty("big", "big new");
        defTest.setProperty("small", "small new");
        defTest.setProperty("mix", "mix new");

        assertEquals("big new", defTest.getProperty("BIG"));
        assertEquals("small new", defTest.getProperty("small"));
        assertEquals("mix new", defTest.getProperty("MiX"));

        assertEquals("big new", defTest.getProperty("big"));
        assertEquals("small new", defTest.getProperty("SMALL"));
        assertEquals("mix new", defTest.getProperty("mIx"));

        defTest.setProperty("BIG", "big new2");
        defTest.setProperty("SMALL", "small new2");
        defTest.setProperty("MIX", "mix new2");

        assertEquals("big new2", defTest.getProperty("BIG"));
        assertEquals("small new2", defTest.getProperty("small"));
        assertEquals("mix new2", defTest.getProperty("MiX"));

        assertEquals("big new2", defTest.getProperty("big"));
        assertEquals("small new2", defTest.getProperty("SMALL"));
        assertEquals("mix new2", defTest.getProperty("mIx"));

        success = false;

        try {
            defTest.setProperty("big", null);
        } catch (NullPointerException e) {
            success = true;
        }

        assertTrue(success);
    }

    //tests the default constructor
    /**
     * DOCUMENT ME!
     */
    public void testConstructor2() {
        CaseInsensitiveProperties defTest = new CaseInsensitiveProperties();

        assertTrue(defTest.getProperty("test") == null);
        assertEquals(defTest.getProperty("BIG"), null);
        assertEquals(defTest.getProperty("small"), null);
        assertEquals(defTest.getProperty("MiX"), null);

        defTest.setProperty("big", "big new");
        defTest.setProperty("small", "small new");
        defTest.setProperty("mix", "mix new");

        assertEquals("big new", defTest.getProperty("BIG"));
        assertEquals("small new", defTest.getProperty("small"));
        assertEquals("mix new", defTest.getProperty("MiX"));

        assertEquals("big new", defTest.getProperty("big"));
        assertEquals("small new", defTest.getProperty("SMALL"));
        assertEquals("mix new", defTest.getProperty("mIx"));

        defTest.setProperty("BIG", "big new2");
        defTest.setProperty("SMALL", "small new2");
        defTest.setProperty("MIX", "mix new2");

        assertEquals("big new2", defTest.getProperty("BIG"));
        assertEquals("small new2", defTest.getProperty("small"));
        assertEquals("mix new2", defTest.getProperty("MiX"));

        assertEquals("big new2", defTest.getProperty("big"));
        assertEquals("small new2", defTest.getProperty("SMALL"));
        assertEquals("mix new2", defTest.getProperty("mIx"));

        boolean success = false;

        try {
            defTest.setProperty("big", null);
        } catch (NullPointerException e) {
            success = true;
        }

        assertTrue(success);

        Properties propTest = new CaseInsensitiveProperties();

        assertTrue(propTest.getProperty("test") == null);
        assertEquals(propTest.getProperty("BIG"), null);
        assertEquals(propTest.getProperty("small"), null);
        assertEquals(propTest.getProperty("MiX"), null);

        propTest.setProperty("big", "big new");
        propTest.setProperty("small", "small new");
        propTest.setProperty("mix", "mix new");

        assertEquals("big new", propTest.getProperty("BIG"));
        assertEquals("small new", propTest.getProperty("small"));
        assertEquals("mix new", propTest.getProperty("MiX"));

        assertEquals("big new", propTest.getProperty("big"));
        assertEquals("small new", propTest.getProperty("SMALL"));
        assertEquals("mix new", propTest.getProperty("mIx"));

        propTest.setProperty("BIG", "big new2");
        propTest.setProperty("SMALL", "small new2");
        propTest.setProperty("MIX", "mix new2");

        assertEquals("big new2", propTest.getProperty("BIG"));
        assertEquals("small new2", propTest.getProperty("small"));
        assertEquals("mix new2", propTest.getProperty("MiX"));

        assertEquals("big new2", propTest.getProperty("big"));
        assertEquals("small new2", propTest.getProperty("SMALL"));
        assertEquals("mix new2", propTest.getProperty("mIx"));

        success = false;

        try {
            propTest.setProperty("big", null);
        } catch (NullPointerException e) {
            success = true;
        }

        assertTrue(success);
    }

    //tests the remove(key);
    /**
     * DOCUMENT ME!
     */
    public void testRemove() {
        CaseInsensitiveProperties propTest = new CaseInsensitiveProperties();
        propTest.setProperty("BIG", "BIG");
        assertEquals(propTest.remove("BIG"), "BIG");
        assertEquals(propTest.getProperty("big"), null);

        propTest.setProperty("BIG", "BIG2");
        assertEquals(propTest.remove("big"), "BIG2");
        assertEquals(propTest.getProperty("big"), null);

        propTest.setProperty("big", "BIG3");
        assertEquals(propTest.remove("BIG"), "BIG3");
        assertEquals(propTest.getProperty("big"), null);

        propTest.setProperty("big", "BIG4");
        assertEquals(propTest.remove("big"), "BIG4");
        assertEquals(propTest.getProperty("big"), null);
    }

    /**
     * DOCUMENT ME!
     */
    public void testGetProperty() {
        CaseInsensitiveProperties propTest = new CaseInsensitiveProperties();
        propTest.setProperty("BIG", "BIG");
        assertEquals(propTest.getProperty("big"), "BIG");
        assertEquals(propTest.getProperty("test"), null);
        assertEquals(propTest.getProperty("big", "test"), "BIG");
        assertEquals(propTest.getProperty("big2", "test"), "test");
        assertEquals(propTest.getProperty("BIG"), "BIG");
        assertEquals(propTest.getProperty("BIG", "TEST"), "BIG");
        assertEquals(propTest.getProperty("BIG2", "test"), "test");
        assertEquals(propTest.getProperty("BIG2"), null);
    }

    /**
     * DOCUMENT ME!
     */
    public void testLoadProperties() {
        CaseInsensitiveProperties propTest = new CaseInsensitiveProperties();
        propTest.setProperty("BIG", "BIG");
        assertEquals(propTest.getProperty("big"), "BIG");

        CaseInsensitiveProperties loadTest = new CaseInsensitiveProperties();
        loadTest.setProperty("BIG", "BIG2");
        propTest.loadProperties(loadTest);
        assertEquals(propTest.getProperty("big"), "BIG2");

        Properties loadTest2 = new Properties();
        loadTest2.setProperty("BIG", "BIG3");
        propTest.loadProperties(loadTest2);
        assertEquals(propTest.getProperty("big"), "BIG3");

        Properties loadTest3 = new Properties();
        loadTest3.setProperty("BIG", "BIG4");

        Properties loadTest4 = new Properties(loadTest3);
        propTest.loadProperties(loadTest4);
        assertEquals(propTest.getProperty("big"), "BIG4");
    }
}
