package org.glite.security.util;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import junit.framework.Test;
import junit.framework.TestSuite;

import org.apache.log4j.Logger;
import org.glite.security.TestBase;


public class CertUtilTest extends TestBase {
    /** DOCUMENT ME! */
    static Logger logger = Logger.getLogger(CertUtilTest.class.getName());

    /**
     * Creates a new FileCertReaderTest object.
     *
     * @param arg0 DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public CertUtilTest(String arg0) throws Exception {
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
        return new TestSuite(CertUtilTest.class);
    }

    /**
     * DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testProxyLoading() {
        try {
            FileCertReader reader = new FileCertReader();
            BufferedInputStream bInputS = new BufferedInputStream(new FileInputStream(m_certHome
                        + "/trusted-certs/trusted_client.proxy.proxy.grid_proxy"));
            KeyStore ks1 = reader.readProxy(bInputS, "changeit");
            String alias = ks1.aliases().nextElement();

            X509Certificate[] chain = (X509Certificate[]) ks1.getCertificateChain(alias);
            
            
            PrivateKey key = (PrivateKey) ks1.getKey(alias, "changeit".toCharArray());
            assertTrue(CertUtil.keysMatch(key, chain[0]));

            assertTrue(chain.length == 3);

            //            System.out.println(chain[0]);
            DN dn = DNHandler.getSubject(chain[0]);
//            System.out.println(dn);
//            System.out.println(dn.getX500());
//            System.out.println(dn.getRFCDN());
//            System.out.println(CertUtil.getUserDN(chain));
//            System.out.println(new DNImpl(
//                    "C=UG,L=Tropic,O=Utopia,OU=Relaxation,CN=trusted client,CN=proxy"));
            assertTrue(dn.equals(
                    new DNImpl("C=UG,L=Tropic,O=Utopia,OU=Relaxation,CN=trusted client,CN=proxy,CN=proxy")));
           
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

}
