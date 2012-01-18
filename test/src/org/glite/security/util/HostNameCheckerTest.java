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
/**
 * 
 */
package org.glite.security.util;

import java.security.cert.X509Certificate;

import junit.framework.Test;
import junit.framework.TestSuite;

import org.glite.security.TestBase;

/**
 * @author Joni Hahkala
 */
public class HostNameCheckerTest extends TestBase {

    /**
     * @param name
     */
    public HostNameCheckerTest(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(HostNameCheckerTest.class);
    }

    /**
     * Test method for
     * {@link org.glite.security.util.HostNameChecker#checkHostName(java.lang.String, java.security.cert.X509Certificate)}
     * .
     */
    public final void testCheckHostName() {
        FileCertReader certReader;
        X509Certificate altnameCert;
		try {
			certReader = new FileCertReader();
			altnameCert = (X509Certificate) certReader.readCerts(m_certHome + "/trusted-certs/trusted_altname.cert")
					.firstElement();
			assertTrue(HostNameChecker.checkHostName("ja.hoo.org", altnameCert));
			assertTrue(HostNameChecker.checkHostName("joo.haa.org", altnameCert));
			assertTrue(HostNameChecker.checkHostName("123.124.220.1", altnameCert));
			assertTrue(HostNameChecker.checkHostName("ga.easda.com", altnameCert));
			assertFalse(HostNameChecker.checkHostName("da.easda.com", altnameCert));
			assertFalse(HostNameChecker.checkHostName("123.124.220.12", altnameCert));
			assertTrue(HostNameChecker.checkHostName("xxx.foo.bar", altnameCert));
			assertFalse(HostNameChecker.checkHostName("ja.ja.hoo.org", altnameCert));

			X509Certificate altname2Cert = (X509Certificate) certReader.readCerts(
					m_certHome + "/trusted-certs/trusted_altname_2.cert").firstElement();
			assertTrue(HostNameChecker.checkHostName("ja.hoo.org", altname2Cert));
			assertTrue(HostNameChecker.checkHostName("joo.haa.org", altname2Cert));
			assertTrue(HostNameChecker.checkHostName("123.124.220.1", altname2Cert));
			assertTrue(HostNameChecker.checkHostName("ga.easda.com", altname2Cert));
			assertFalse(HostNameChecker.checkHostName("da.easda.com", altname2Cert));
			assertFalse(HostNameChecker.checkHostName("123.124.220.12", altname2Cert));
			assertTrue(HostNameChecker.checkHostName("xxx.foo.bar", altname2Cert));
			assertFalse(HostNameChecker.checkHostName("ja.ja.hoo.org", altname2Cert));

			X509Certificate dnsDNCert = (X509Certificate) certReader.readCerts(
					m_certHome + "/trusted-certs/trusted_server2.cert").firstElement();
			assertFalse(HostNameChecker.checkHostName("ja.hoo.org", dnsDNCert));
			assertFalse(HostNameChecker.checkHostName("joo.haa.org", dnsDNCert));
			assertFalse(HostNameChecker.checkHostName("123.124.220.1", dnsDNCert));
			assertFalse(HostNameChecker.checkHostName("ga.easda.com", dnsDNCert));
			assertFalse(HostNameChecker.checkHostName("da.easda.com", dnsDNCert));
			assertFalse(HostNameChecker.checkHostName("123.124.220.12", dnsDNCert));
			assertTrue(HostNameChecker.checkHostName("xxx2.foo.bar", dnsDNCert));
			assertFalse(HostNameChecker.checkHostName("ja.ja.hoo.org", dnsDNCert));
			
			X509Certificate cert = (X509Certificate) certReader.readCerts(
					m_utilJavaRoot + "/test/input/hostcert-email.pem").firstElement();

			assertTrue(HostNameChecker.checkHostName("http://wilco.cnaf.infn.it:8443/test", cert));
			assertTrue(HostNameChecker.checkHostName("wilco.cnaf.infn.it", cert));
			assertFalse(HostNameChecker.checkHostName("xxx.cnaf.infn.it", cert));
			
			X509Certificate cert2 = (X509Certificate) certReader.readCerts(
					m_certHome + "/trusted-certs/trusted_host_email.cert").firstElement();

			assertTrue(HostNameChecker.checkHostName("http://pchip10.cern.ch:8443/test", cert2));
			assertTrue(HostNameChecker.checkHostName("pchip10.cern.ch", cert2));
			assertFalse(HostNameChecker.checkHostName("xxx.cnaf.infn.it", cert2));

			X509Certificate cert3 = (X509Certificate) certReader.readCerts(
					m_certHome + "/trusted-certs/trusted_altname3_2.cert").firstElement();

			assertTrue(HostNameChecker.checkHostName("http://pchip10.cern.ch:8443/test", cert3));
			assertTrue(HostNameChecker.checkHostName("pchip10.cern.ch", cert3));
			assertFalse(HostNameChecker.checkHostName("xxx.cnaf.infn.it", cert3));
		} catch (Exception e) {
			e.printStackTrace();
			throw new IllegalArgumentException(e);
		}

    }

}
