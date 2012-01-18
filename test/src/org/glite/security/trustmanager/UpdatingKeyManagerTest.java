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

package org.glite.security.trustmanager;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import junit.framework.TestSuite;

import org.apache.log4j.Logger;
import org.glite.security.TestBase;
import org.glite.security.util.CaseInsensitiveProperties;

/**
 * @author hahkala
 */
public class UpdatingKeyManagerTest extends TestBase {
    /** DOCUMENT ME! */
    static Logger LOGGER = Logger.getLogger(UpdatingKeyManagerTest.class.getName());

    /**
     * @param arg0
     */
    public UpdatingKeyManagerTest(String arg0) {
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
    public static TestSuite suite() {
        TestSuite suite = new TestSuite(UpdatingKeyManagerTest.class);

        return suite;
    }

    /**
     * DOCUMENT ME!
     */
    @SuppressWarnings("null")
	public void testConstructor() throws Exception {
//        Logger LOGGERRoot = Logger.getLogger("org.glite.security");
//        Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %c{2}%l %x - %m%n");
//        Appender appender = new ConsoleAppender(lay);
//        LOGGERRoot.addAppender(appender);
//        LOGGERRoot.setLevel(Level.DEBUG);
        boolean exceptionThrown = false;
        CaseInsensitiveProperties props = new CaseInsensitiveProperties();
        UpdatingKeyManager keyManager;
        try {
            props.setProperty(ContextWrapper.CREDENTIALS_CERT_FILE, m_utilJavaRoot + "/test/input/hostcert-old.pem");
            props.setProperty(ContextWrapper.CREDENTIALS_KEY_FILE, m_utilJavaRoot + "/test/input/trusted_client.proxy.priv");
            keyManager = new UpdatingKeyManager(props, null);
        } catch (CertificateException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        exceptionThrown = false;
        try {
            props.setProperty(ContextWrapper.CREDENTIALS_CERT_FILE, m_utilJavaRoot + "/test/input/hostcert-new.pem");
            props.setProperty(ContextWrapper.CREDENTIALS_KEY_FILE, m_utilJavaRoot + "/test/input/trusted_client.proxy.priv");

            keyManager = new UpdatingKeyManager(props, null);
        } catch (CertificateException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);

        props.setProperty(ContextWrapper.CREDENTIALS_CERT_FILE, m_utilJavaRoot + "/test/input/trusted_client.proxy.cert");
        props.setProperty(ContextWrapper.CREDENTIALS_KEY_FILE, m_utilJavaRoot + "/test/input/trusted_client.proxy.priv");

        keyManager = new UpdatingKeyManager(props, null);

        exceptionThrown = false;
        try {
            props.setProperty(ContextWrapper.CREDENTIALS_CERT_FILE, m_utilJavaRoot + "/test/input/trusted_client.proxy.cert");
            props.setProperty(ContextWrapper.CREDENTIALS_KEY_FILE, m_utilJavaRoot + "/test/input/trusted_client.proxy.invalid.priv");

            keyManager = new UpdatingKeyManager(props, null);
        } catch (CertificateException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);
        String alias = keyManager.chooseServerAlias("RSA", null, null);
        X509Certificate[] cert = keyManager.getCertificateChain(alias);
        assertFalse(cert == null);
        assertTrue(cert.length == 1);

    }
}
