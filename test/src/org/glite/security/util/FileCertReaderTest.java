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

import java.io.BufferedInputStream;
import java.io.FileInputStream;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;


/**
 *
 * @author  Joni Hahkala <joni.hahkala@cern.ch>
 */
public class FileCertReaderTest extends TestBase {
    /** DOCUMENT ME! */
    static Logger logger = Logger.getLogger(FileCertReaderTest.class.getName());

    /**
     * Creates a new FileCertReaderTest object.
     *
     * @param arg0 DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public FileCertReaderTest(String arg0) throws Exception {
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
        return new TestSuite(FileCertReaderTest.class);
    }

    /**
     * DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testProxyLoading() {
        try {
            FileCertReader reader = new FileCertReader();
            BufferedInputStream bInputS = new BufferedInputStream(new FileInputStream(m_certHome
                        + "/trusted-certs/trusted_client.proxy.grid_proxy"));
            KeyStore ks1 = reader.readProxy(bInputS, "changeit");
            String alias = ks1.aliases().nextElement();

            X509Certificate[] chain = (X509Certificate[]) ks1.getCertificateChain(alias);
            PrivateKey key = (PrivateKey) ks1.getKey(alias, "changeit".toCharArray());
            assertTrue(CertUtil.keysMatch(key, chain[0]));

            assertTrue(chain.length == 2);

            //            System.out.println(chain[0]);
            DN dn = DNHandler.getSubject(chain[0]);
//            System.out.println(dn);
//            System.out.println(dn.getX500());
//            System.out.println(dn.getRFC2253());
//            System.out.println(new DNImpl(
//                    "C=UG,L=Tropic,O=Utopia,OU=Relaxation,CN=trusted client,CN=proxy"));
            assertTrue(dn.equals(
                    new DNImpl("C=UG,L=Tropic,O=Utopia,OU=Relaxation,CN=trusted client,CN=proxy")));

            //            PublicKey pubKey;
            bInputS = new BufferedInputStream(new FileInputStream(m_utilJavaRoot
                        + "/test/input/KCA_test_cert.pem"));

            KeyStore ks2 = reader.readProxy(bInputS, "changeit");
            String alias2 = ks2.aliases().nextElement();

            X509Certificate[] chain2 = (X509Certificate[]) ks2.getCertificateChain(alias2);
            assertTrue(chain2.length == 1);
            
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * DOCUMENT ME!
     */
    public void testKCAProxyLoading() {
        try {
            FileCertReader reader = new FileCertReader();
            BufferedInputStream bInputS = new BufferedInputStream(new FileInputStream(m_utilJavaRoot
                        + "/test/input/KCA_test_cert.pem"));
            KeyStore ks1 = reader.readProxy(bInputS, "changeit");
            String alias = ks1.aliases().nextElement();

            X509Certificate[] chain = (X509Certificate[]) ks1.getCertificateChain(alias);
            PrivateKey key = (PrivateKey) ks1.getKey(alias, "changeit".toCharArray());

            //            System.out.println(chain.length);
            assertTrue(chain.length == 1);
            assertTrue(CertUtil.keysMatch(key, chain[0]));

            //            System.out.println(chain[0]);
            //            PublicKey pubKey;
//            DN dn = DNHandler.getSubject(chain[0]);
//            System.out.println(dn);
//            System.out.println(dn.getX500());
//            System.out.println(dn.getRFC2253());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * DOCUMENT ME!
     */
//    public void testAnchorLoading() {
//    }

    /**
     * DOCUMENT ME!
     */
//    public void testCertLoading() {
//    }
}
