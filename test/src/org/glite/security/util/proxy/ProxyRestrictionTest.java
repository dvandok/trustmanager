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
package org.glite.security.util.proxy;


import java.io.IOException;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.glite.security.util.IPAddressComparator;

public class ProxyRestrictionTest extends TestCase {
    
    private static final String[] validIPv4Addresses = {"127.0.0.1/24", "123.123.0.2/16"};
    private static final String[] validIPv6Addresses = {"::1/1", "FFFF:FFFF::FFFF/32"};

    public ProxyRestrictionTest(String arg0) throws Exception {
        super(arg0);
    }
    
    public static Test suite() {
        return new TestSuite(ProxyRestrictionTest.class);
    }

    /**
     * Test that what you generate is parsed the same way.
     */
    public void testGenerationParsing(){
        ProxyRestrictionData inputData = new ProxyRestrictionData();
        inputData.addPermittedIPAddressWithNetmask(validIPv4Addresses[0]);
        inputData.addExcludedIPAddressWithNetmask(validIPv4Addresses[1]);
        inputData.addPermittedIPAddressWithNetmask(validIPv6Addresses[0]);
        inputData.addExcludedIPAddressWithNetmask(validIPv6Addresses[1]);

        ProxyRestrictionData output = null;
        try {
            byte[] bits = inputData.getNameConstraints().getEncoded();
//            FileOutputStream writer = new FileOutputStream("testrestriction.der");
//            writer.write(bits);
            output = new ProxyRestrictionData(bits);
//            writer.close();
        } catch (IOException e) {
            
            e.printStackTrace();
            fail("Proxy restrtiction data parsing failed.");
            return;
        }
        byte[][][] addressSpaces = output.getIPSpaces();
        assertTrue(addressSpaces.length == 2);
        
        
        
/*        int i,n;
        System.out.println(addressSpaces[0].length+":"+addressSpaces[1].length);
        for (i=0; i < addressSpaces[0].length; i++){
            System.out.print("[0][" + i+ "]: ");
            for(n = 0; n<addressSpaces[0][i].length; n++){
                System.out.print((addressSpaces[0][i][n] < 0? addressSpaces[0][i][n]+256:addressSpaces[0][i][n])+ " ");
            }
            System.out.println();
        }
        for (i=0; i < addressSpaces[1].length; i++){
            System.out.print("[1][" + i+ "]: ");
            for(n = 0; n<addressSpaces[1][i].length; n++){
                System.out.print((addressSpaces[1][i][n] < 0? addressSpaces[1][i][n]+256:addressSpaces[1][i][n]) + " ");
            }
            System.out.println();
        }
*/        
        assertTrue(addressSpaces[0].length == 2);
        assertTrue(addressSpaces[1].length == 2);
        assertTrue(IPAddressComparator.compare(addressSpaces[0][0], IPAddressComparator.parseIP(validIPv4Addresses[0])));
        assertTrue(IPAddressComparator.compare(addressSpaces[1][0], IPAddressComparator.parseIP(validIPv4Addresses[1])));
        assertTrue(IPAddressComparator.compare(addressSpaces[0][1], IPAddressComparator.parseIP(validIPv6Addresses[0])));
        assertTrue(IPAddressComparator.compare(addressSpaces[1][1], IPAddressComparator.parseIP(validIPv6Addresses[1])));
        
        
    }
}
