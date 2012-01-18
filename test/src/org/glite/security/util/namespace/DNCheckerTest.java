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
package org.glite.security.util.namespace;

import java.io.IOException;
import java.security.cert.CertPathValidatorException;
import java.text.ParseException;
import java.util.List;

import org.apache.log4j.Appender;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.glite.security.util.DNHandler;

import junit.framework.Assert;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;


/**
 * @author hahkala
 *
 */
public class DNCheckerTest extends TestCase {
    /** Creates a new instance of DNCheckerTest */
    public DNCheckerTest(String arg0) throws Exception {
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
        try {
            return new TestSuite(DNCheckerTest.class);
        } catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
    }
    
    @SuppressWarnings("deprecation")
    public void testDNConstraintsTest(){
    	NamespaceFormat namespace = new EUGridNamespaceFormat();
    	try {
			namespace.parse("test/input/test.namespace");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		boolean failed = false;
		
		List<NamespacePolicy> policies = namespace.getPolices();
		DNCheckerImpl checker = new DNCheckerImpl();
		try {
			checker.check(DNHandler.getDN("/C=DE/O=GridGermany/CN=john doe"), DNHandler.getDN("/C=DE/O=DFN-Verein/OU=DFN-PKI/CN=CA Grid"), policies);
		} catch (CertPathValidatorException e) {
			Assert.fail("User DN \"/C=DE/O=GridGermany/CN=john doe\" and CA \"/C=DE/O=DFN-Verein/OU=DFN-PKI/CN=CA Grid\" should not fail");
		}
		try {
			checker.check(DNHandler.getDN("/C=DE/O=GridGermany/CN=john doe"), DNHandler.getDN("/C=DE/O=DFN-Verein/OU=DFN-PKI/CN=CA Grid invalid"), policies);
		} catch (CertPathValidatorException e) {
			failed = true;
		}
		assertTrue("The CA \"/C=DE/O=DFN-Verein/OU=DFN-PKI/CN=CA Grid invalid\" should fail", failed);
		failed = false;
		try {
			checker.check(DNHandler.getDN("/C=DE/O=GridGermanyInvalid/CN=john doe"), DNHandler.getDN("/C=DE/O=DFN-Verein/OU=DFN-PKI/CN=CA Grid"), policies);
		} catch (CertPathValidatorException e) {
			failed = true;
		}
		assertTrue("The subject DN \"/C=DE/O=GridGermanyInvalid/CN=john doe\" should fail", failed);
  	
    }
    
    @SuppressWarnings("deprecation")
    public void testDNChinaTest(){
        NamespaceFormat namespace = new EUGridNamespaceFormat();
        try {
            namespace.parse("test/input/testChina.namespace");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        List<NamespacePolicy> policies = namespace.getPolices();
        DNCheckerImpl checker = new DNCheckerImpl();
        try {
            checker.check(DNHandler.getDN("/C=CN/O=HEP/O=CCNU/OU=PHYS/CN=jianlin zhu"), DNHandler.getDN("/C=CN/O=HEP/CN=gridca-cn/Email=gridca@ihep.ac.cn"), policies);
        } catch (CertPathValidatorException e) {
            e.printStackTrace();
            Assert.fail("User DN \"/C=CN/O=HEP/O=CCNU/OU=PHYS/CN=jianlin zhu\" and CA \"/C=CN/O=HEP/CN=gridca-cn/Email=gridca@ihep.ac.cn\" should not fail");
        }    
    }
    
    @SuppressWarnings("deprecation")
    public void testDNCERNTest(){
        NamespaceFormat namespace = new EUGridNamespaceFormat();
        try {
            namespace.parse("test/input/testCERN.namespace");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        List<NamespacePolicy> policies = namespace.getPolices();
        DNCheckerImpl checker = new DNCheckerImpl();
        try {
            checker.check(DNHandler.getDN("/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=wlapka/CN=623537/CN=Wojciech Lapka"), DNHandler.getDN("/DC=ch/DC=cern/CN=CERN Trusted Certification Authority"), policies);
        } catch (CertPathValidatorException e) {
            e.printStackTrace();
            Assert.fail("User DN \"/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=wlapka/CN=623537/CN=Wojciech Lapka\" and CA \"/DC=ch/DC=cern/CN=CERN Trusted Certification Authority\" should not fail");
        }    
    }
    
    @SuppressWarnings("deprecation")
    public void testDNCERN2Test(){
        NamespaceFormat namespace = new LegacyNamespaceFormat();
        try {
            namespace.parse("test/input/testCERN2.signing_policy");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        List<NamespacePolicy> policies = namespace.getPolices();
        DNCheckerImpl checker = new DNCheckerImpl();
        try {
            checker.check(DNHandler.getDN("/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=wlapka/CN=623537/CN=Wojciech Lapka"), DNHandler.getDN("/DC=ch/DC=cern/CN=CERN Trusted Certification Authority"), policies);
        } catch (CertPathValidatorException e) {
            e.printStackTrace();
            Assert.fail("User DN \"/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=wlapka/CN=623537/CN=Wojciech Lapka\" and CA \"/DC=ch/DC=cern/CN=CERN Trusted Certification Authority\" should not fail");
        }    
    }
    
    @SuppressWarnings("deprecation")
    public void testDNConstraints2Test(){
        NamespaceFormat namespace = new EUGridNamespaceFormat();
        try {
            namespace.parse("test/input/test2.namespace");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
//        boolean failed = false;
        
        List<NamespacePolicy> policies = namespace.getPolices();
        DNCheckerImpl checker = new DNCheckerImpl();
        try {
            checker.check(DNHandler.getDN("/DC=org/DC=doegrids/OU=People/CN=Igor Sfiligoi 673872"), DNHandler.getDN("/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1"), policies);
        } catch (CertPathValidatorException e) {
            Assert.fail("User DN \"/DC=org/DC=doegrids/OU=People/CN=Igor Sfiligoi 673872\" and CA \"/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1\" should not fail");
        }
    
        try {
            checker.check(DNHandler.getDN("/DC=org/DC=DOEGrids/OU=People/CN=Igor Sfiligoi 673872"), DNHandler.getDN("/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1"), policies);
        } catch (CertPathValidatorException e) {
            Assert.fail("User DN \"/DC=org/DC=DOEGrids/OU=People/CN=Igor Sfiligoi 673872\" and CA \"/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1\" should not fail");
        }
    
        try {
            checker.check(DNHandler.getDN("/O=DOEGrids.org/OU=People/CN=Igor Sfiligoi 673872"), DNHandler.getDN("/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1"), policies);
        } catch (CertPathValidatorException e) {
            Assert.fail("User DN \"/O=DOEGrids.org/OU=People/CN=Igor Sfiligoi 673872\" and CA \"/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1\" should not fail");
        }
    
        try {
            checker.check(DNHandler.getDN("/O=doegrids.org/OU=People/CN=Igor Sfiligoi 673872"), DNHandler.getDN("/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1"), policies);
        } catch (CertPathValidatorException e) {
            Assert.fail("User DN \"/O=doegrids.org/OU=People/CN=Igor Sfiligoi 673872\" and CA \"/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1\" should not fail");
        }
    
        boolean exception = false;
        try {
            checker.check(DNHandler.getDN("/O=doegrids.orgi/OU=People/CN=Igor Sfiligoi 673872"), DNHandler.getDN("/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1"), policies);
        } catch (CertPathValidatorException e) {
            exception = true;
        }
        assertTrue(exception);
    
        exception = false;
        try {
            checker.check(DNHandler.getDN("/DC=org/DC=DOEGridsi/OU=People/CN=Igor Sfiligoi 673872"), DNHandler.getDN("/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1"), policies);
        } catch (CertPathValidatorException e) {
            exception = true;
        }
        assertTrue(exception);
    
    }
    
    @SuppressWarnings("deprecation")
    public void testDNConstraints2_2Test(){
        NamespaceFormat namespace = new LegacyNamespaceFormat();
        try {
            namespace.parse("test/input/test2.signing_policy");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
//        boolean failed = false;
        
        List<NamespacePolicy> policies = namespace.getPolices();
        DNCheckerImpl checker = new DNCheckerImpl();
        try {
            checker.check(DNHandler.getDN("/DC=org/DC=doegrids/OU=People/CN=Igor Sfiligoi 673872"), DNHandler.getDN("/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1"), policies);
        } catch (CertPathValidatorException e) {
            Assert.fail("User DN \"/DC=org/DC=doegrids/OU=People/CN=Igor Sfiligoi 673872\" and CA \"/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1\" should not fail");
        }
    
    }
    public void testDNConstraintsAAA(){
        Logger LOGGERRoot = Logger.getLogger("org.glite.security");
        Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %c{2}%l %x - %m%n");
        Appender appender = new ConsoleAppender(lay);
        LOGGERRoot.addAppender(appender);
        LOGGERRoot.setLevel(Level.INFO);
        NamespaceFormat namespace = new LegacyNamespaceFormat();
        try {
            namespace.parse("test/input/testAAA.signing_policy");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            Assert.fail("User DN \"/C=US/ST=UT/L=Salt Lake City/O=The USERTRUST Network/OU=http://www.usertrust.com/CN=UTN-USERFirst-Client Authentication and Email\" and CA \"/C=GB/ST=Greater Manchester/L=Salford/O=Comodo CA Limited/CN=AAA Certificate Services\" should not fail");
        } catch (ParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            Assert.fail("User DN \"/C=US/ST=UT/L=Salt Lake City/O=The USERTRUST Network/OU=http://www.usertrust.com/CN=UTN-USERFirst-Client Authentication and Email\" and CA \"/C=GB/ST=Greater Manchester/L=Salford/O=Comodo CA Limited/CN=AAA Certificate Services\" should not fail");
        }
        
//        boolean failed = false;
        
        List<NamespacePolicy> policies = namespace.getPolices();
        DNCheckerImpl checker = new DNCheckerImpl();
        try {
            checker.check(DNHandler.getDNRFC2253("/C=US/ST=UT/L=Salt Lake City/O=The USERTRUST Network/OU=http://www.usertrust.com/CN=UTN-USERFirst-Client Authentication and Email"), DNHandler.getDNRFC2253("/C=GB/ST=Greater Manchester/L=Salford/O=Comodo CA Limited/CN=AAA Certificate Services"), policies);
        } catch (CertPathValidatorException e) {
            Assert.fail("User DN \"/C=US/ST=UT/L=Salt Lake City/O=The USERTRUST Network/OU=http://www.usertrust.com/CN=UTN-USERFirst-Client Authentication and Email\" and CA \"/C=GB/ST=Greater Manchester/L=Salford/O=Comodo CA Limited/CN=AAA Certificate Services\" should not fail");
        }
        LOGGERRoot.setLevel(Level.INFO);
    
    }
    
    public void testLoadSigningPolicy() throws Exception {
        NamespaceFormat namespace = new LegacyNamespaceFormat();
        boolean exception = false;
        try{
            namespace.parse("test/input/caMissValue.signing_policy");
        } catch (Exception e){
            exception = true;
        }
        assertTrue(exception);
        
        exception = false;
        try{
            namespace.parse("test/input/caMissX509Field.signing_policy");
        } catch (Exception e){
            exception = true;
        }
        assertTrue(exception);
        
        exception = false;
        try{
            namespace.parse("test/input/condMissGlobusField.signing_policy");
        } catch (Exception e){
            exception = true;
        }
        assertTrue(exception);
        
        exception = false;
        try{
            namespace.parse("test/input/condMissValue.signing_policy");
        } catch (Exception e){
            exception = true;
        }
        assertTrue(exception);
        
        exception = false;
        try{
            namespace.parse("test/input/missCA.signing_policy");
        } catch (Exception e){
            exception = true;
        }
        assertTrue(exception);
        
        exception = false;
        try{
            namespace.parse("test/input/missCond.signing_policy");
        } catch (Exception e){
            exception = true;
        }
        assertTrue(exception);
        
        exception = false;
        try{
            namespace.parse("test/input/missRight.signing_policy");
        } catch (Exception e){
            exception = true;
        }
        assertTrue(exception);
        
        exception = false;
        try{
            namespace.parse("test/input/rightMissGlobusField.signing_policy");
        } catch (Exception e){
            exception = true;
        }
        assertTrue(exception);
        
        exception = false;
        try{
            namespace.parse("test/input/rightMissValue.signing_policy");
        } catch (Exception e){
            exception = true;
        }
        assertTrue(exception);
                
    }
    
    
}
