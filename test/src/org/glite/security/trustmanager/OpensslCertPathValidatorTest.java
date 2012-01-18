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

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Vector;

import junit.framework.TestSuite;

import org.apache.log4j.Appender;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.glite.security.TestBase;
import org.glite.security.util.CaseInsensitiveProperties;
import org.glite.security.util.FileCertReader;

/**
 * ProxyCertPathValidatorTest.java
 * 
 * @author Joni Hahkala Created on September 23, 2002, 6:03 PM
 */
public class OpensslCertPathValidatorTest extends TestBase {
	/** DOCUMENT ME! */
	static Logger LOGGER = Logger.getLogger(OpensslCertPathValidatorTest.class.getName());

	/** DOCUMENT ME! */
	static FileCertReader s_certReader = null;

	/** DOCUMENT ME! */
	String m_gliteSecurityHome;

	/** DOCUMENT ME! */
	boolean m_isSetup = false;

	/** DOCUMENT ME! */
	public TestItem[] m_trustedCerts;

	/** DOCUMENT ME! */
	public TestItem[] m_trustedRevokedCerts;

	/** DOCUMENT ME! */
	public TestItem[] m_trustedProxies;

	/** DOCUMENT ME! */
	public TestItem[] m_trustedRevokedProxies;

	/** DOCUMENT ME! */
	public TestItem[] m_fakeCerts;

	/** DOCUMENT ME! */
	public TestItem[] m_fakeProxies;

	/** DOCUMENT ME! */
	public TestItem[] m_miscProxies;

	/** DOCUMENT ME! */
    public TestItem[] m_subsubProxies;

    /** DOCUMENT ME! */
    public TestItem[] m_subsubRevokedProxies;

    /** DOCUMENT ME! */
    public TestItem[] m_subsubBadDNProxies;

    /** DOCUMENT ME! */
    public TestItem[] m_bigProxies;
    
    public TestItem[] m_trustedCertsForNoCRL;

	/** Creates a new instance of ProxyCertPathValidatorTest. */
	public OpensslCertPathValidatorTest(final String name) {
		super(name);
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @param load DOCUMENT ME!
	 * @throws Exception DOCUMENT ME!
	 */
	void setup(final boolean load) throws Exception {
		if (m_isSetup) {
			return;
		}

		Vector<TestItem> certs = new Vector<TestItem>();
		certs.addElement(new TestItem("trusted-certs/trusted_client", false, true, load));
		certs.addElement(new TestItem("trusted-certs/trusted_client_exp", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_clientserver", false, true, load));
		certs.addElement(new TestItem("trusted-certs/trusted_clientserver_exp", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_fclient", false, true, load));
		certs.addElement(new TestItem("trusted-certs/trusted_fclient_exp", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_none", false, true, load));
		certs.addElement(new TestItem("trusted-certs/trusted_none_exp", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_server", false, true, load));
		certs.addElement(new TestItem("trusted-certs/trusted_server_exp", false, false, load));
		m_trustedCerts = certs.toArray(new TestItem[0]);

		certs = new Vector<TestItem>();
		certs.addElement(new TestItem("trusted-certs/trusted_client_rev", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_clientserver_rev", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_fclient_rev", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_none_rev", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_server_rev", false, false, load));
		m_trustedRevokedCerts = certs.toArray(new TestItem[0]);

		certs = new Vector<TestItem>();
		certs.addElement(new TestItem("trusted-certs/trusted_client_exp.proxy.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_client.proxy.grid_proxy", true, true, load));
		certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_exp.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_clientserver_exp.proxy.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_clientserver.proxy.grid_proxy", true, true, load));
		certs.addElement(new TestItem("trusted-certs/trusted_clientserver.proxy_exp.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_fclient_exp.proxy.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_fclient.proxy.grid_proxy", true, true, load));
		certs.addElement(new TestItem("trusted-certs/trusted_fclient.proxy_exp.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_none_exp.proxy.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_none.proxy.grid_proxy", true, true, load));
		certs.addElement(new TestItem("trusted-certs/trusted_none.proxy_exp.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_server_exp.proxy.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_server.proxy.grid_proxy", true, true, load));
		certs.addElement(new TestItem("trusted-certs/trusted_server.proxy_exp.grid_proxy", true, false, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_rfc.grid_proxy", true, true, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_rfc_plen.proxy_rfc.proxy_rfc.grid_proxy", true, false, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_rfc_plen.proxy_rfc.grid_proxy", true, true, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_rfc_lim.grid_proxy", true, true, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_rfc.proxy.grid_proxy", true, false, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_rfc_lim.proxy_rfc.grid_proxy", true, true, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_rfc.proxy_rfc_lim.grid_proxy", true, true, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_rfc_anyp.grid_proxy", true, true, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_rfc_indep.grid_proxy", true, true, load));
		
		m_trustedProxies = certs.toArray(new TestItem[0]);

		// revoked certs, by default they should fail
		certs = new Vector<TestItem>();
		certs.addElement(new TestItem("trusted-certs/trusted_client_rev.proxy.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_clientserver_rev.proxy.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_fclient_rev.proxy.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_none_rev.proxy.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_server_rev.proxy.grid_proxy", true, false, load));
		m_trustedRevokedProxies = certs.toArray(new TestItem[0]);

		certs = new Vector<TestItem>();
		certs.addElement(new TestItem("fake-certs/fake_client", false, false, load));
		certs.addElement(new TestItem("fake-certs/fake_client.proxy", false, false, load));
		m_fakeCerts = certs.toArray(new TestItem[0]);

		certs = new Vector<TestItem>();
		certs.addElement(new TestItem("fake-certs/fake_client.proxy.grid_proxy", true, false, load));
		m_fakeProxies = certs.toArray(new TestItem[0]);

		certs = new Vector<TestItem>();
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_dnerror2.grid_proxy", true, false, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_dnerror.grid_proxy", true, false, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_dnerror.proxy.grid_proxy", true, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_client.proxy.proxy_dnerror.grid_proxy", true, false, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_exp.proxy.grid_proxy", true, false, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy_exp.proxy_exp.grid_proxy", true, false, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy.proxy_exp.grid_proxy", true, false, load));
        certs.addElement(new TestItem("trusted-certs/trusted_client.proxy.proxy.grid_proxy", true, true, load));
		certs.addElement(new TestItem("trusted-certs/trusted_bigclient",false, true, load));
        
		m_miscProxies = certs.toArray(new TestItem[0]);

        certs = new Vector<TestItem>();
        certs.addElement(new TestItem("subsubca-certs/subsubca_fullchainclient.proxy.grid_proxy", true, true, load));
        certs.addElement(new TestItem("subsubca-certs/subsubca_fullchainclient.proxy.proxy.grid_proxy", true, true, load));
        certs.addElement(new TestItem("subsubca-certs/subsubca_client.proxy.grid_proxy", true, true, load));
        certs.addElement(new TestItem("subsubca-certs/subsubca_client.proxy.proxy.grid_proxy", true, true, load));

        m_subsubProxies = certs.toArray(new TestItem[0]);
		
        certs = new Vector<TestItem>();
        certs.addElement(new TestItem("subsubca-certs/subsubca_client_rev.proxy.grid_proxy", true, false, load));
        certs.addElement(new TestItem("subsubca-certs/subsubca_client_rev.proxy.proxy.grid_proxy", true, false, load));

        m_subsubRevokedProxies = certs.toArray(new TestItem[0]);
        
        certs = new Vector<TestItem>();
        certs.addElement(new TestItem("subsubca-certs/subsubca_clientbaddn.proxy.grid_proxy", true, false, load));
        certs.addElement(new TestItem("subsubca-certs/subsubca_clientbaddn.proxy.proxy.grid_proxy", true, false, load));

        m_subsubBadDNProxies = certs.toArray(new TestItem[0]);
        
        certs = new Vector<TestItem>();
        certs.addElement(new TestItem("big-certs/big_client.proxy.grid_proxy", true, true, load));
        certs.addElement(new TestItem("big-certs/big_client.proxy.proxy.grid_proxy", true, true, load));

        m_bigProxies = certs.toArray(new TestItem[0]);
        
		certs = new Vector<TestItem>();
		certs.addElement(new TestItem("trusted-certs/trusted_client", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_client_exp", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_clientserver", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_clientserver_exp", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_fclient", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_fclient_exp", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_none", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_none_exp", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_server", false, false, load));
		certs.addElement(new TestItem("trusted-certs/trusted_server_exp", false, false, load));
		m_trustedCertsForNoCRL = certs.toArray(new TestItem[0]);
        
		m_isSetup = true;
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
		TestSuite suite = new TestSuite(OpensslCertPathValidatorTest.class);

		return suite;
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @param validator DOCUMENT ME!
	 * @param testItem DOCUMENT ME!
	 * @param reverse whether test that is expected normally to succeed should fail or if normally failing test should succeed.
	 * @throws Exception DOCUMENT ME!
	 */
	public void doTest(final OpensslCertPathValidator validator, final TestItem testItem, final boolean reverse)
			throws Exception {
	    
	    boolean newException = false;
	    Exception thrownException = null;
	    // exception get the value of reversal
//		boolean exception = reverse;
	    String dn = testItem.m_chain[0].getSubjectDN().getName();
		LOGGER.debug("testing: " + dn);

		try {
			validator.check(testItem.m_chain);
		} catch (Exception e) {
			// reverse exception to opposite of reversal
//		    exception = !reverse;
		    newException = true;
		    thrownException = e;
		    
		    // if reversal is false and success expected and exception is thrown, throw e, to mark failure.
//			if (testItem.m_ok == exception) {
//				throw e;
//			}
		}
		
		if(testItem.m_ok ^ reverse ^ !newException){
		    LOGGER.error("Test of cert "+ testItem.m_chain[0].getSubjectDN() + " from "+testItem.m_fileName+" didn't go as planned, test was expected to " +  ((testItem.m_ok ^ reverse)?"succeed":"fail") + " and it " + (newException?"failed":"succeeded")+".");
		    if(thrownException != null){
		        LOGGER.error("Unwanted exception was: " + thrownException.getMessage(), thrownException);
		    }
		    System.out.println("Test of cert "+ testItem.m_chain[0].getSubjectDN() + " from "+testItem.m_fileName+" didn't go as planned, test was expected to " +  ((testItem.m_ok ^ reverse)?"succeed":"fail") + " and it " + (newException?"failed":"succeeded")+".");
		    assertTrue(false);
		}
		
//		assertTrue(testItem.m_ok != exception);
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @param validator DOCUMENT ME!
	 * @param testItems DOCUMENT ME!
	 * @param reverse DOCUMENT ME!
	 * @throws Exception DOCUMENT ME!
	 */
	public void doTests(final OpensslCertPathValidator validator, final TestItem[] testItems, final boolean reverse)
			throws Exception {
		int n;

		for (n = 0; n < testItems.length; n++) {
			LOGGER.info("Testing item: " + n);
			doTest(validator, testItems[n], reverse);
		}
	}

	/**
	 * Check with crls required and present
	 * 
	 * @throws Exception DOCUMENT ME!
	 */
	@SuppressWarnings("deprecation")
    public void testCheckSimple() throws Exception {
		setup(true);

		OpensslCertPathValidator validator = new OpensslCertPathValidator(m_certHome + "/grid-security/certificates/", true);

        doTests(validator, m_bigProxies, false);
		doTests(validator, m_subsubBadDNProxies, false);
        doTests(validator, m_subsubRevokedProxies, false);
        doTests(validator, m_subsubProxies, false);
        doTests(validator, m_miscProxies, false);
		doTests(validator, m_trustedCerts, false);
		doTests(validator, m_trustedRevokedCerts, false);
		doTests(validator, m_trustedProxies, false);
		doTests(validator, m_trustedRevokedProxies, false);
		doTests(validator, m_fakeCerts, false);
		doTests(validator, m_fakeProxies, false);
	}

	/**
	 * check with crls not required and not present.
	 * 
	 * @throws Exception DOCUMENT ME!
	 */
	@SuppressWarnings("deprecation")
    public void testCheckCRL() throws Exception {
		setup(true);
		OpensslCertPathValidator validator = new OpensslCertPathValidator(m_certHome + "/grid-security/certificates-withoutCrl/", false);

        Logger LOGGERRoot = Logger.getLogger("org.glite.security");
        Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %c{2}%l %x - %m%n");
        Appender appender = new ConsoleAppender(lay);
        LOGGERRoot.addAppender(appender);
        LOGGERRoot.setLevel(Level.INFO);

        doTests(validator, m_bigProxies, false);
        LOGGERRoot.setLevel(Level.INFO);
        doTests(validator, m_subsubBadDNProxies, false);
        doTests(validator, m_subsubRevokedProxies, true);
        doTests(validator, m_subsubProxies, false);
		doTests(validator, m_trustedCerts, false);
		doTests(validator, m_trustedRevokedCerts, true);
		doTests(validator, m_trustedProxies, false);
		doTests(validator, m_trustedRevokedProxies, true);
		doTests(validator, m_fakeCerts, false);
		doTests(validator, m_fakeProxies, false);
		doTests(validator, m_miscProxies, false);
		
		validator = new OpensslCertPathValidator(m_certHome + "/grid-security/certificates-withoutCrl/", true);
		doTests(validator, m_trustedCertsForNoCRL, false);
		

	}

	/**
	 * check with crls not required and not present.
	 * 
	 * @throws Exception DOCUMENT ME!
	 */
	@SuppressWarnings("deprecation")
    public void testCheckCRLnew() throws Exception {
		setup(true);
		CaseInsensitiveProperties props = new CaseInsensitiveProperties();
		props.put(ContextWrapper.CRL_ENABLED, "true");
		props.put(ContextWrapper.CRL_REQUIRED, "false");
		
		OpensslCertPathValidator validator = new OpensslCertPathValidator(m_certHome + "/grid-security/certificates-withoutCrl/", false, null);

        Logger LOGGERRoot = Logger.getLogger("org.glite.security");
        Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %c{2}%l %x - %m%n");
        Appender appender = new ConsoleAppender(lay);
        LOGGERRoot.addAppender(appender);
        LOGGERRoot.setLevel(Level.INFO);

        doTests(validator, m_bigProxies, false);
        LOGGERRoot.setLevel(Level.INFO);
        doTests(validator, m_subsubBadDNProxies, false);
        doTests(validator, m_subsubRevokedProxies, true);
        doTests(validator, m_subsubProxies, false);
		doTests(validator, m_trustedCerts, false);
		doTests(validator, m_trustedRevokedCerts, true);
		doTests(validator, m_trustedProxies, false);
		doTests(validator, m_trustedRevokedProxies, true);
		doTests(validator, m_fakeCerts, false);
		doTests(validator, m_fakeProxies, false);
		doTests(validator, m_miscProxies, false);
		
//		validator = new OpensslCertPathValidator(m_certHome + "/grid-security/certificates-withoutCrl/", false, null);
//		doTests(validator, m_trustedCertsForNoCRL, true);
		

	}

	/**
	 * check with crls not required and not present.
	 * 
	 * @throws Exception DOCUMENT ME!
	 */
	@SuppressWarnings("deprecation")
    public void testCheckCRLnew2() throws Exception {
		setup(true);
		CaseInsensitiveProperties props = new CaseInsensitiveProperties();
		props.put(ContextWrapper.CRL_ENABLED, "false");
		props.put(ContextWrapper.CRL_REQUIRED, "false");
		
		OpensslCertPathValidator validator = new OpensslCertPathValidator(m_certHome + "/grid-security/certificates-withoutCrl/", false, props);

        Logger LOGGERRoot = Logger.getLogger("org.glite.security");
        Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %c{2}%l %x - %m%n");
        Appender appender = new ConsoleAppender(lay);
        LOGGERRoot.addAppender(appender);
        LOGGERRoot.setLevel(Level.INFO);

        doTests(validator, m_bigProxies, false);
        LOGGERRoot.setLevel(Level.INFO);
        doTests(validator, m_subsubBadDNProxies, false);
        doTests(validator, m_subsubRevokedProxies, true);
        doTests(validator, m_subsubProxies, false);
		doTests(validator, m_trustedCerts, false);
		doTests(validator, m_trustedRevokedCerts, true);
		doTests(validator, m_trustedProxies, false);
		doTests(validator, m_trustedRevokedProxies, true);
		doTests(validator, m_fakeCerts, false);
		doTests(validator, m_fakeProxies, false);
		doTests(validator, m_miscProxies, false);
		
//		validator = new OpensslCertPathValidator(m_certHome + "/grid-security/certificates-withoutCrl/", false, props);
//		doTests(validator, m_trustedCertsForNoCRL, false);
		

	}
	/**
	 * DOCUMENT ME!
	 * 
	 * @throws Exception DOCUMENT ME!
	 */
	@SuppressWarnings("deprecation")
    public void testCheckCRLreq() throws Exception {
		setup(true);

		OpensslCertPathValidator validator = new OpensslCertPathValidator(m_certHome + "/grid-security/certificates-withoutCrl/", true);

		doTest(validator, m_trustedCerts[0], true);
		doTest(validator, m_trustedRevokedCerts[0], false);
	}

    /**
     * check with crls not required and not present.
     * 
     * @throws Exception DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testCheckRootPolicy() throws Exception {
        setup(true);

        OpensslCertPathValidator validator = new OpensslCertPathValidator(m_certHome + "/grid-security/certificates-rootwithpolicy/", false);

        doTests(validator, m_subsubBadDNProxies, false);
        doTests(validator, m_subsubRevokedProxies, false);
        doTests(validator, m_subsubProxies, false);
    }

    /**
     * check with crls not required and not present.
     * 
     * @throws Exception DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testCheckSubPolicy() throws Exception {
        setup(true);

        OpensslCertPathValidator validator = new OpensslCertPathValidator(m_certHome + "/grid-security/certificates-subcawithpolicy/", false);

        doTests(validator, m_subsubBadDNProxies, false);
        doTests(validator, m_subsubRevokedProxies, false);
        doTests(validator, m_subsubProxies, false);
    }

    /**
     * check with crls not required and not present.
     * 
     * @throws Exception DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testCheckRootAllowSubsubDenyPolicy() throws Exception {
        setup(true);

        OpensslCertPathValidator validator = new OpensslCertPathValidator(m_certHome + "/grid-security/certificates-rootallowsubsubdeny/", false);

        doTests(validator, m_subsubBadDNProxies, false);
        doTests(validator, m_subsubRevokedProxies, false);
        doTests(validator, m_subsubProxies, true);
    }
    
    @SuppressWarnings("deprecation")
    public void testSlash() throws Exception {
//        Logger LOGGERRoot = Logger.getLogger("org.glite.security");
//        Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %c{2}%l %x - %m%n");
//        Appender appender = new ConsoleAppender(lay);
//        LOGGERRoot.addAppender(appender);
//        LOGGERRoot.setLevel(Level.DEBUG);
        OpensslCertPathValidator validator = new OpensslCertPathValidator(m_utilJavaRoot + "/test/certs/grid-security/certificates", false);
        Vector<?> certs = s_certReader.readCerts(m_utilJavaRoot + "/test/certs/slash-certs/slash_client_slash.cert");

        X509Certificate[] chain = certs.toArray(new X509Certificate[0]);
        if(chain.length < 1){
            throw new Exception("cert loading of \"" + m_utilJavaRoot + "/test/certs/slash-certs/slash_client_slash.cert" + "\" failed.");
        }
        
        validator.check(chain);
//        LOGGERRoot.setLevel(Level.INFO);
    }

	/**
	 * DOCUMENT ME!
	 */
	public class TestItem {
		/** DOCUMENT ME! */
		X509Certificate[] m_chain;

		/** DOCUMENT ME! */
		boolean m_ok;

		/** DOCUMENT ME! */
		public String m_fileName;

		/** DOCUMENT ME! */
		boolean m_proxy;

		/**
		 * Creates a new TestItem object.
		 * 
		 * @param certFile DOCUMENT ME!
		 * @param isProxy DOCUMENT ME!
		 * @param isok DOCUMENT ME!
		 * @param load DOCUMENT ME!
		 * @throws Exception DOCUMENT ME!
		 */
		public TestItem(final String certFile, final boolean isProxy, final boolean isok, final boolean load)
				throws Exception {
			if (s_certReader == null) {
				s_certReader = new FileCertReader();
			}

			m_ok = isok;
			m_proxy = isProxy;
			m_fileName = m_certHome + "/" + certFile;

			if (load) {
				if (isProxy) {
					KeyStore keyStore = s_certReader.readProxy(
							new BufferedInputStream(new FileInputStream(m_fileName)), "test");
					m_chain = (X509Certificate[]) keyStore.getCertificateChain("host");
				} else {
					Vector<?> certs = s_certReader.readCerts(m_fileName + ".cert");

					m_chain = certs.toArray(new X509Certificate[0]);
					if(m_chain.length < 1){
					    throw new Exception("cert loading of \"" + m_fileName+ "\" failed.");
					}
				}
			}
		}
	}
}
