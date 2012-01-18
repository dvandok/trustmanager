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

import java.security.cert.X509Certificate;
import java.util.Random;

import junit.framework.Test;
import junit.framework.TestSuite;

import org.glite.security.util.DNHandler;
import org.glite.security.util.FileCertReader;


/**
 * @author Olle Mulmo, Joni Hahkala
 *
 * To change this generated comment edit the template variable "typecomment":
 * Window>Preferences>Java>Templates.
 * To enable and disable the creation of type comments go to
 * Window>Preferences>Java>Code Generation.
 */
public class SecurityContextTest extends TestBase {
    /** DOCUMENT ME! */
    SecurityContext sc;

    //    AuthorizationManager am0;
    /** DOCUMENT ME! */
    String p;

    /** DOCUMENT ME! */
    String policy = "policy".intern();

    /** DOCUMENT ME! */
    String cn;

    /** DOCUMENT ME! */
    String clientName = "client name".intern();

    /** DOCUMENT ME! */
    String in;

    /** DOCUMENT ME! */
    String issuerName = "issuer name".intern();

    /** DOCUMENT ME! */
    X509Certificate proxyCert;

    /** DOCUMENT ME! */
    X509Certificate userCert;

    /** DOCUMENT ME! */
    X509Certificate caCert;

    /** DOCUMENT ME! */
    X509Certificate[] c;

    /** DOCUMENT ME! */
    X509Certificate[] certChain;

    /** DOCUMENT ME! */
    int success;

    /** DOCUMENT ME! */
    int finished;

    /**
     * Creates a new SecurityContextTest object.
     *
     * @param arg0 DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public SecurityContextTest(String arg0) throws Exception {
        super(arg0);
        sc = new SecurityContext();
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
        return new TestSuite(SecurityContextTest.class);
    }

    /**
     * DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    protected void setUp() throws Exception {
        super.setUp();

        //        am = new AuthorizationManager();
        FileCertReader certReader = new FileCertReader();

        proxyCert = (X509Certificate) certReader.readCerts(m_certHome
                + "/trusted-certs/trusted_client.proxy.grid_proxy").firstElement();
        userCert = (X509Certificate) certReader.readCerts(m_certHome
                + "/trusted-certs/trusted_client.cert").firstElement();
        caCert = (X509Certificate) certReader.readCerts(m_certHome + "/trusted-ca/trusted.cert")
                                             .firstElement();
        certChain = new X509Certificate[] { proxyCert, userCert, caCert };

        //        sc.setAuthorizationManager(am);
//        sc.setAuthorizationPolicy(policy);
//        sc.setAuthorizedAttributes(approved);
        sc.setClientCertChain(certChain);
        sc.setClientName(clientName);
        sc.setIssuerName(issuerName);
//        sc.setRequestedAttributes(requested);
    }

    /**
     * DOCUMENT ME!
     *
     * @param label DOCUMENT ME!
     * @param original DOCUMENT ME!
     * @param fetched DOCUMENT ME!
     */
    public void verify(String label, Object original, Object fetched) {
        assertNotNull(original);
        assertSame(sc.get(label), fetched);
        assertSame(original, fetched);
    }

    //    public void testAuthorizationManager() {
    /**
     * DOCUMENT ME!
     */
    public void testAuthorizationPolicy() {
//        verify(SecurityContext.AUTHZ_POLICY, policy, sc.getAuthorizationPolicy());
    }

    /**
     * DOCUMENT ME!
     */
    public void testAuthorizedAttributes() {
//        verify(SecurityContext.AUTHZ_APPROVED_ATTRIBUTES, approved, sc.getAuthorizedAttributes());
    }

    /**
     * DOCUMENT ME!
     */
    public void testClientCertChain() {
        verify(SecurityContext.CERT_CHAIN, certChain, sc.getClientCertChain());
    }

    /**
     * DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testClientName() {
        verify(SecurityContext.CLIENT_NAME, clientName, sc.getClientName());
    }

    /**
     * DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testIssuerName() {
        verify(SecurityContext.ISSUER_NAME, issuerName, sc.getIssuerName());
    }

    /**
     * DOCUMENT ME!
     */
    public void testRequestedAttributes() {
//        verify(SecurityContext.AUTHZ_REQUESTED_ATTRIBUTES, requested, sc.getRequestedAttributes());
    }

    /**
     * DOCUMENT ME!
     */
    public void funcTestThreading() {
        final Random r = new Random();
        success = 0;
        finished = 0;

        int i = 0;
        int count = 100;

        while (i++ < count) {
            new Thread("Thread #" + i) {
                    public void run() {
                        try {
                            try {
                                Thread.sleep(r.nextInt(1000));
                            } catch (InterruptedException e) {
                            	// don't care
                            }

                            Long myNum = new Long(r.nextLong());
                            SecurityContext sc1 = new SecurityContext();
                            SecurityContext.setCurrentContext(sc1);
                            sc1.put("test", myNum);

                            try {
                                Thread.sleep(r.nextInt(3000));
                            } catch (InterruptedException e) {
                            	// don't care
                            }

                            Long l = (Long) SecurityContext.getCurrentContext().get("test");

                            if (l.longValue() == myNum.longValue()) {
                                success++;
                            }
                        } finally {
                            finished++;
                        }
                    }
                }.start();
        }

        while (finished < count) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
            	// don't care
            }
        }

        assertEquals(success, finished);
    }

    // The strange name is to ensure that it will run last...
    /**
     * DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testZzzCertChainAgain() {
        // these may be redefined by setCertChain()
        Object o;
        sc.remove(SecurityContext.ISSUER_NAME);
        sc.remove(SecurityContext.CLIENT_NAME);

        sc.setClientCertChain(certChain);

        assertNotNull(o = sc.getClientName());
        assertEquals(o, DNHandler.getSubject(userCert).getRFC2253());
        assertNotNull(o = sc.getIssuerName());
        assertEquals(o, DNHandler.getSubject(caCert).getRFC2253());
        assertNotNull(o = sc.getClientDN());
        assertEquals(o, DNHandler.getSubject(userCert));
        assertNotNull(o = sc.getIssuerDN());
        assertEquals(o, DNHandler.getSubject(caCert));
        
        sc.setClientDN(DNHandler.getSubject(proxyCert));
        assertEquals(sc.getClientDN(), DNHandler.getSubject(proxyCert));
        sc.setIssuerDN(DNHandler.getIssuer(proxyCert));
        assertEquals(sc.getIssuerDN(), DNHandler.getIssuer(proxyCert));
        
    }
}
