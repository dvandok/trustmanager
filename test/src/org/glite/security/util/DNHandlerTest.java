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

import java.security.Principal;

import javax.management.remote.JMXPrincipal;

import junit.framework.Test;
import junit.framework.TestSuite;

import org.apache.log4j.Appender;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;
import org.glite.security.TestBase;


/**
 *
 * Testing the DNHandler.
 *
 * Tests the DNHandler and DNImpl classes.
 *
 * @author  Joni Hahkala
 * Created on August 26, 2003, 10:38 AM
 */
public class DNHandlerTest extends TestBase {
    /** Test logger. */
    static final Logger LOGGER = Logger.getLogger(DNHandlerTest.class.getName());

    /** test string. */
    static final String TEST_1 = "EMAILADDRESS=Vincenzo.Ciaschini@cnaf.infn.it,CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN,C=IT";
    /** test string. */
    static final String TEST_1_1 = "emailAddress=Vincenzo.Ciaschini@cnaf.infn.it,CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN,C=IT";
    /** test string. */
    static final String TEST_2 = "Email=Vincenzo.Ciaschini@cnaf.infn.it,CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN,C=IT";
    /** test string. */
    static final String TEST_3 = "E=Vincenzo.Ciaschini@cnaf.infn.it,CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN,C=IT";
    /** test string. */
    static final String TEST_4 = "C=IT,O=INFN,OU=cas server,L=Bologna,CN=cas/aaa-test.cnaf.infn.it,E=Vincenzo.Ciaschini@cnaf.infn.it";
    /** test string. */
    static final String TEST_5 = "C=IT,O=INFN,OU=cas server,L=Bologna,CN=cas/aaa-test.cnaf.infn.it,Email=Vincenzo.Ciaschini@cnaf.infn.it";
    /** test string. */
    static final String TEST_6 = "C=UG,L=Tropic,O=Utopia,OU=Relaxation,CN=Trusted server,CN=proxy";
    /** test string. */
    static final String TEST_7 = "C=UG,L=Tropic,O=Utopia,OU=Relaxation,CN=Trusted server";
    /** test string. */
    static final String TEST_8 = "/C=US/ST=UT/L=Salt Lake City/O=The USERTRUST Network/OU=http://www.usertrust.com/CN=UTN-USERFirst-Client Authentication and Email";
    /** test string. */
    static final String TEST_9 = "CN=UTN-USERFirst-Client Authentication and Email,OU=http://www.usertrust.com,O=The USERTRUST Network,L=Salt Lake City,ST=UT,C=US";
    /** test string. */
    static final String TEST_10 = "/C=//hkjh///ST=UT/L=Salt Lake City/O=The USERTRUST Network/OU=http://www.usertrust.com/CN=UTN-USERFirst-Client Authentication and Email/CN=test";
    /** test string. */
    static final String SNTEST_1 = "C=UG,L=Tropic,O=Utopia,OU=Relaxation,CN=Trusted server,SN=1234123";
    /** test string. */
    static final String SNTEST_2 = "C=UG,L=Tropic,O=Utopia,OU=Relaxation,CN=Trusted server,SERIALNUMBER=1234123";
    /** test string. */
    static final String SNTEST_3 = "/C=UG/L=Tropic/O=Utopia/OU=Relaxation/CN=Trusted server/SERIALNUMBER=1234123";

    /**
     * Creates a new instance of DNHandlerTest
     *
     * @param arg0 not used.
     */
    public DNHandlerTest(String arg0) {
        super(arg0);
    }

    /**
     * Support running this test class separately.
     *
     * @param args not used.
     */
    public static void main(java.lang.String[] args) {
        junit.textui.TestRunner.run(suite());
    }

    /**
     * Base test suite.
     *
     * @return The test framwork.
     */
    public static Test suite() {
        return new TestSuite(DNHandlerTest.class);
    }

    /**
     * Test the RFC format from Principal input.
     */
    @SuppressWarnings("deprecation")
    public void testRFCFromPrincipal() {
        /*        X509Certificate caCert=null, ca2Cert=null, sunCaCert=null, sunCa2Cert=null;
           try{
               String certFile = "/etc/grid-security/certificates/c4435d12.0";
               String cert2File = "/etc/grid-security/certificates/747183a5.0";
               FileCertReader certReader = new FileCertReader();
               caCert = (X509Certificate) certReader.readCerts(certFile).firstElement();
               ca2Cert = (X509Certificate) certReader.readCerts(cert2File).firstElement();
               CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "SUN");
               certReader.certFactory=certFactory;
               sunCaCert = (X509Certificate) certReader.readCerts(certFile).firstElement();
               sunCa2Cert = (X509Certificate) certReader.readCerts(cert2File).firstElement();
           }catch (Exception e){
               e.printStackTrace();
           }
           try{
           System.out.println(caCert.getClass().getName());
           System.out.println(caCert.getSubjectDN());
           System.out.println(DNHandler.getSubject(caCert).toString());
           System.out.println(DNHandler.getSubject(caCert).getX500());
           System.out.println(DNHandler.getSubject(caCert).getRFC2253());
           System.out.println(ca2Cert.getSubjectDN());
           System.out.println(DNHandler.getSubject(ca2Cert).toString());
           System.out.println(DNHandler.getSubject(ca2Cert).getX500());
           System.out.println(DNHandler.getSubject(ca2Cert).getRFC2253());
           System.out.println("------------------------------");
           System.out.println(sunCaCert.getClass().getName());
           System.out.println(sunCaCert.getSubjectDN());
           System.out.println(DNHandler.getSubject(sunCaCert).toString());
           System.out.println(DNHandler.getSubject(sunCaCert).getX500());
           System.out.println(DNHandler.getSubject(sunCaCert).getRFC2253());
           System.out.println(sunCa2Cert.getSubjectDN());
           System.out.println(DNHandler.getSubject(sunCa2Cert).toString());
           System.out.println(DNHandler.getSubject(sunCa2Cert).getX500());
           System.out.println(DNHandler.getSubject(sunCa2Cert).getRFC2253());
           System.out.println("=================================");
           System.out.println(DNHandler.getDN(new X500Principal("CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US")).getX500());
           System.out.println(DNHandler.getDN(new X509Principal("CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US")).getX500());
           System.out.println(DNHandler.getDN(new X500Principal("CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US")).getRFC2253());
           System.out.println(DNHandler.getDN(new X509Principal("CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US")).getRFC2253());
           System.out.println(new X500Principal("CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US"));
           System.out.println(new X509Principal("CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US"));
           System.out.println("****************************");
           System.out.println(DNHandler.getDN(new X500Principal("C=US, O=Sun Microsystems, OU=JavaSoft, CN=Duke")).getX500());
           System.out.println(DNHandler.getDN(new X509Principal("C=US, O=Sun Microsystems, OU=JavaSoft, CN=Duke")).getX500());
           System.out.println(DNHandler.getDN(new sun.security.x509.X500Name("CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US")).getRFC2253());
           System.out.println(DNHandler.getDN(new X509Principal("C=US, O=Sun Microsystems, OU=JavaSoft, CN=Duke")).getRFC2253());
           System.out.println(new X500Principal("C=US, O=Sun Microsystems, OU=JavaSoft, CN=Duke"));
           System.out.println(new X500Principal("C=US, O=Sun Microsystems, OU=JavaSoft, CN=Duke").getName());
           System.out.println(new X509Principal("C=US, O=Sun Microsystems, OU=JavaSoft, CN=Duke"));
           }catch(Exception e){
               System.out.println("Exception caught ");
               e.printStackTrace();
           }
         */
        assertEquals("C=US,O=Sun Microsystems,OU=JavaSoft,CN=Duke", DNHandler.getDN(
                new X509Name("C=US,O=Sun Microsystems,OU=JavaSoft,CN=Duke")).getRFC2253());
        // test with deprecaed method
        assertEquals("C=US,O=Sun Microsystems,OU=JavaSoft,CN=Duke", DNHandler.getDN(
                new X509Name("C=US,O=Sun Microsystems,OU=JavaSoft,CN=Duke")).getRFC2253());
    }

    /**
     * Test the RFC format from string input.
     */
    @SuppressWarnings("deprecation")
    public void testRFCFromString() {
        assertEquals("CN=First Middle Last,OU=OrgUnit,O=Org,C=ZZ", DNHandler.getDN(
                "CN=First Middle Last,OU=OrgUnit,O=Org,C=ZZ").getRFC2253());
        assertEquals(DNHandler.getDN("CN=First Middle Last,OU=OrgUnit,O=Org,C=ZZ"), DNHandler
                .getDN("CN=First Middle Last,OU=OrgUnit,O=Org,C=ZZ"));
        assertEquals("CN=First Middle Last,OU=OrgUnit,O=Org,C=ZZ", DNHandler.getDN(
                " CN=First Middle Last , OU=OrgUnit , O=Org , C=ZZ ").getRFC2253());
        assertEquals("C=ZZ,O=Org,OU=OrgUnit,CN=First Middle Last", DNHandler.getDNRFC2253(
                " CN=First Middle Last , OU=OrgUnit , O=Org , C=ZZ ").getRFC2253());
        assertEquals("C=ZZ,O=Org,OU=OrgUnit,CN=First Middle Last", DNHandler.getDN(
                " CN=First Middle Last , OU=OrgUnit , O=Org , C=ZZ ").getRFCDN());
        assertEquals("CN=First Middle Last,OU=OrgUnit,O=Org,C=ZZ", DNHandler.getDNRFC2253(
                " CN=First Middle Last , OU=OrgUnit , O=Org , C=ZZ ").getRFCDN());
        assertEquals(DNHandler.getDN("CN=First Middle Last,OU=OrgUnit,O=Org,C=ZZ"), DNHandler
                .getDN(" CN=First Middle Last , OU=OrgUnit , O=Org , C=ZZ "));
        assertEquals("CN=Robert ,Bob, Hacker,O=Org", DNHandler.getDN("CN=Robert \",Bob,\" Hacker,O=Org").getRFC2253());
        assertEquals(DNHandler.getDN("CN=Robert \",Bob,\" Hacker,O=Org"), DNHandler
                .getDN("CN=Robert \",Bob,\" Hacker,O=Org"));
        assertEquals("CN=L. Eagle,O=Sue, Grabbit and Runn,C=GB", DNHandler.getDN(
                "CN=L. Eagle\\ ,O=Sue\\, Grabbit and Runn,C=GB").getRFC2253());
        assertEquals(DNHandler.getDN("CN=L. Eagle\\ ,O=Sue\\, Grabbit and Runn,C=GB"), DNHandler
                .getDN("CN=L. Eagle\\ ,O=Sue\\, Grabbit and Runn,C=GB"));
        assertEquals("CN=CERN dummy CA/emailAddress=Foo.Bar@cern.ch,O=EDG,C=CH", DNHandler.getDN(
                "CN=CERN dummy CA/emailAddress=Foo.Bar@cern.ch, O=EDG, C=CH").getRFC2253());
        assertEquals(DNHandler.getDN("CN=CERN dummy CA/emailAddress=Foo.Bar@cern.ch, O=EDG, C=CH"), DNHandler
                .getDN("CN=CERN dummy CA/emailAddress=Foo.Bar@cern.ch, O=EDG, C=CH"));

        assertEquals(SNTEST_2, DNHandler.getDN(SNTEST_1).getRFC2253());
        assertEquals(SNTEST_2, DNHandler.getDN(SNTEST_2).getRFC2253());
        
        assertEquals(TEST_1_1, DNHandler.getDN(TEST_1).getRFC2253v2());
        assertEquals(SNTEST_3, DNHandler.getDN(SNTEST_1).getX500());

        boolean exception = false;

        try {
            DNHandler.getDN("CN=L. Eagle\\ ,O=Sue, Grabbit and Runn,C=GB");
        } catch (IllegalArgumentException e) {
            exception = true;
        }

        assertTrue(exception);
        
        // tests with deprecated methods------------------------------------------------------------
        assertEquals("CN=First Middle Last,OU=OrgUnit,O=Org,C=ZZ", DNHandler.getDN(
                "CN=First Middle Last,OU=OrgUnit,O=Org,C=ZZ").getRFC2253());
        assertEquals(DNHandler.getDN("CN=First Middle Last,OU=OrgUnit,O=Org,C=ZZ"), DNHandler
                .getDN("CN=First Middle Last,OU=OrgUnit,O=Org,C=ZZ"));
        assertEquals("CN=First Middle Last,OU=OrgUnit,O=Org,C=ZZ", DNHandler.getDN(
                " CN=First Middle Last , OU=OrgUnit , O=Org , C=ZZ ").getRFC2253());
        assertEquals(DNHandler.getDN("CN=First Middle Last,OU=OrgUnit,O=Org,C=ZZ"), DNHandler
                .getDN(" CN=First Middle Last , OU=OrgUnit , O=Org , C=ZZ "));
        assertEquals("CN=Robert ,Bob, Hacker,O=Org", DNHandler.getDN("CN=Robert \",Bob,\" Hacker,O=Org").getRFC2253());
        assertEquals(DNHandler.getDN("CN=Robert \",Bob,\" Hacker,O=Org"), DNHandler
                .getDN("CN=Robert \",Bob,\" Hacker,O=Org"));
        assertEquals("CN=L. Eagle,O=Sue, Grabbit and Runn,C=GB", DNHandler.getDN(
                "CN=L. Eagle\\ ,O=Sue\\, Grabbit and Runn,C=GB").getRFC2253());
        assertEquals(DNHandler.getDN("CN=L. Eagle\\ ,O=Sue\\, Grabbit and Runn,C=GB"), DNHandler
                .getDN("CN=L. Eagle\\ ,O=Sue\\, Grabbit and Runn,C=GB"));
        assertEquals("CN=CERN dummy CA/emailAddress=Foo.Bar@cern.ch,O=EDG,C=CH", DNHandler.getDN(
                "CN=CERN dummy CA/emailAddress=Foo.Bar@cern.ch, O=EDG, C=CH").getRFC2253());
        assertEquals(DNHandler.getDN("CN=CERN dummy CA/emailAddress=Foo.Bar@cern.ch, O=EDG, C=CH"), DNHandler
                .getDN("CN=CERN dummy CA/emailAddress=Foo.Bar@cern.ch, O=EDG, C=CH"));

        assertEquals(SNTEST_2, DNHandler.getDN(SNTEST_1).getRFC2253());
        assertEquals(SNTEST_2, DNHandler.getDN(SNTEST_2).getRFC2253());

        exception = false;

        try {
            DNHandler.getDN("CN=L. Eagle\\ ,O=Sue, Grabbit and Runn,C=GB");
        } catch (IllegalArgumentException e) {
            exception = true;
        }

        assertTrue(exception);
    }

    /**
     * Test the X500 format.
     */
    @SuppressWarnings("deprecation")
    public void testX500FromString() {
/*        System.out.println(DNHandler.getDN("C=CH, O=EDG, emailAddress=Olle.Mulmo@cern.ch").getX500());
           System.out.println(DNHandler.getDN("C=CH, O=EDG, emailAddress=Olle.Mulmo@cern.ch").getRFC2253());
*/
        assertEquals("/C=CH/O=EDG/Email=Olle.Mulmo@cern.ch", DNHandler.getDN("C=CH, O=EDG, emailAddress=Olle.Mulmo@cern.ch").getX500());
        assertEquals("/Email=Vincenzo.Ciaschini@cnaf.infn.it/CN=cas/aaa-test.cnaf.infn.it/L=Bologna/OU=cas server/O=INFN/C=IT"
            , DNHandler.getDN(TEST_1).getX500());
        assertEquals(SNTEST_3, DNHandler.getDN(SNTEST_1).getX500());
        assertEquals(SNTEST_3, DNHandler.getDN(SNTEST_2).getX500());
        assertEquals(TEST_9, DNHandler.getDNRFC2253(TEST_8).getRFCDN());
        assertEquals(TEST_10, DNHandler.getDNRFC2253(TEST_10).getX500());
    }
    
    public void testPrincipalInput(){
//      Logger LOGGERRoot = Logger.getLogger("org.glite.security");
//      Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %c{2}%l %x - %m%n");
//      Appender appender = new ConsoleAppender(lay);
//      LOGGERRoot.addAppender(appender);
//      LOGGERRoot.setLevel(Level.DEBUG);
	
    	Principal principal = new X509Principal("C=IT,O=INFN,OU=cas server,L=Bologna,CN=cas/aaa-test.cnaf.infn.it,Emailaddress=Vincenzo.Ciaschini@cnaf.infn.it");
    	DN dn = DNHandler.getDN(principal);
    	assertTrue(dn.getRFCDN().equals("Email=Vincenzo.Ciaschini@cnaf.infn.it,CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN,C=IT"));
    	Principal principal2 = new JMXPrincipal("Emailaddress=Vincenzo.Ciaschini@cnaf.infn.it,CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN,C=IT");
    	DN dn2 = DNHandler.getDN(principal2);
    	assertTrue(dn2.getRFCDN().equals("Email=Vincenzo.Ciaschini@cnaf.infn.it,CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN,C=IT"));
    	Principal principal3 = new JMXPrincipal("CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN,C=IT");
    	DN dn3 = DNHandler.getDN(principal3);
    	assertTrue(dn3.getRFCDN().equals("CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN,C=IT"));
    	Principal principal4 = new JMXPrincipal("C=IT,O=INFN,OU=cas server,L=Bologna,CN=cas/aaa-test.cnaf.infn.it");
    	DN dn4 = DNHandler.getDN(principal4);
    	assertTrue(dn4.getRFCDN().equals("CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN,C=IT"));
    	
    	Principal principal5 = new JMXPrincipal("O=INFN,OU=cas server,L=Bologna,CN=cas/aaa-test.cnaf.infn.it");
    	DN dn5 = DNHandler.getDN(principal5);
    	assertEquals(dn5.getRFCDN(),"CN=cas/aaa-test.cnaf.infn.it,L=Bologna,OU=cas server,O=INFN");
    	
    }

    /**
     * Placeholder for equals testing, done in DNTest already.
     */
    public void testEquals() {
        // done in DNTest;
    }
}
