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

import java.io.File;

import junit.framework.TestCase;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.helpers.NullEnumeration;

/**
 * The base class for the security tests that need access to the files in the build/cvs checkout.
 * 
 * @author Joni Hahkala
 */
public class TestBase extends TestCase {
    /** The default base directory for security tests. */
    public static final String GLITE_SECURITY_HOME = "..";

    /** the system variable to use to get the security tests base dir. */
    public static final String GLITE_SECURITY_HOME_STRING = "gliteSecurity.home";

    /** the default stage directory. */
    public static final String GLITE_SECURITY_STAGE_DEFAULT = "../stage";

    /** the system variable to read for the stage directory */
    public static final String GLITE_SECURITY_STAGE_STRING = "stage.abs.dir";

    /** the logging facility. */
    static final Logger LOGGER = Logger.getLogger(TestBase.class.getName());
    
    private static long lastTime = System.currentTimeMillis();

    /** the base directory for security tests. */
    public String m_utilJavaRoot;

    /** the base directory for test certificates. */
    public String m_certHome;

    /**
     * Creates a new TestBase object.
     * 
     * @param arg0 not used.
     */
    public TestBase(String arg0) {
        super(arg0);

        m_utilJavaRoot = initEnv();
        m_certHome = m_utilJavaRoot + "/test/certs";

        if (System.getProperty("utilJavaQuiet") == null) {
            PropertyConfigurator.configure(m_utilJavaRoot + "/test/conf/log4j.properties");

            // if no configuration given and logging is not setup, output to console and set level to WARN
            final Layout lay = new PatternLayout("%-5p %d{dd MMM yyyy HH:mm:ss,SSS} [%t] %c %x: %m%n");

            if (LOGGER.getAllAppenders() instanceof NullEnumeration) {
                BasicConfigurator.configure(new ConsoleAppender(lay));

                Logger parent = Logger.getLogger("org.glite.security");
                parent.setLevel(Level.WARN);
            }
        } else {
            Logger parent = Logger.getLogger("org.glite.security");
            parent.setLevel(Level.OFF);

        }

    }

    /**
     * Initializes the security tests base directory.
     * 
     * @return the base directory.
     */
    public static String initEnv() {
        String gliteSecurityHome = System.getProperty(GLITE_SECURITY_HOME_STRING);
        if (gliteSecurityHome == null) {
            if (new File("test/conf/log4j.properties").exists()) {
                gliteSecurityHome = ".";
            } else {
                if (new File("org.glite.security.util-java/test/conf/log4j.properties").exists()) {
                    gliteSecurityHome = "org.glite.security.util-java";
                } else {
                    throw new AssertionError("Could nod determine the util-java roor dir.");
                }
            }
        }
        return gliteSecurityHome;
    }
    
    static public void printInterval(){
    	long newTime = System.currentTimeMillis();
    	System.out.println("Interval = " + (newTime - lastTime));
    	lastTime = newTime;
    }
    
    static public void printInterval(String string){
    	long newTime = System.currentTimeMillis();
    	System.out.println("Interval " + string + " = " + (newTime - lastTime));
    	lastTime = newTime;
    }
}
