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
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author hahkala
 */
public class IPAddressComparatorTest extends TestCase {

    /**
     * @param name
     */
    public IPAddressComparatorTest(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(IPAddressComparatorTest.class);
    }

    public void testCompare() {
        byte[][] ips = { { -1, -1, -1, -1 }, { -1, -1, -1, 0 }, { -1, -1, 0, 0 }, { -1, 0, 0, 0 }, { 0, 0, 0, 0 },
                { 123, 123, 123, 123 } };
        byte[][] ipmasks = { { -1, -1, -1, -1, -1, -1, -1, -1 }, { -1, -1, -1, 0, -1, -1, -1, -1 },
                { -1, -1, 0, 0, -1, -1, -1, -1 }, { -1, 0, 0, 0, -1, -1, 0, -1 }, { 0, 0, 0, 0, -1, -1, -1, 0 },
                { 123, 123, 123, 123, -1, -1, 0, -1 } };
        byte[][] ipv6s = { { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
                { -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
                { -1, -1, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
                { -1, 0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
                { 0, 0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
                { 123, 123, 123, 123, 123, 123, 1, 123, 123, 7, 123, 123, 123, 123, 8, 123 } };
        byte[][] ipv6masks = {
                { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
                { -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
                { -1, -1, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
                { -1, 0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
                { 0, 0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
                { 123, 123, 123, 123, 123, 123, 1, 123, 123, 7, 123, 123, 123, 123, 8, 123, 
                    123, 123, 10, 123, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 } };

        for (int i = 0; i < ips.length; i++) {
            for (int n = 0; n < ips.length; n++) {
                boolean result = IPAddressComparator.compare(ips[i], ips[n]);
                if (result == true) {
                    assertTrue(i == n);
                } else {
                    assertTrue(i != n);
                }
            }
        }
        for (int i = 0; i < ipmasks.length; i++) {
            for (int n = 0; n < ipmasks.length; n++) {
                boolean result = IPAddressComparator.compare(ipmasks[i], ipmasks[n]);
                if (result == true) {
                    assertTrue(i == n);
                } else {
                    assertTrue(i != n);
                }
            }
        }
        for (int i = 0; i < ipv6s.length; i++) {
            for (int n = 0; n < ipv6s.length; n++) {
                boolean result = IPAddressComparator.compare(ipv6s[i], ipv6s[n]);
                if (result == true) {
                    assertTrue(i == n);
                } else {
                    assertTrue(i != n);
                }
            }
        }
        for (int i = 0; i < ipv6masks.length; i++) {
            for (int n = 0; n < ipv6masks.length; n++) {
                boolean result = IPAddressComparator.compare(ipv6masks[i], ipv6masks[n]);
                if (result == true) {
                    assertTrue(i == n);
                } else {
                    assertTrue(i != n);
                }
            }
        }
        // test that different size arrays produce false.

        boolean exception = false;
        try {
            IPAddressComparator.compare(new byte[] { 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85 },
                    new byte[] { -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86 });
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
        exception = false;
        try {
            IPAddressComparator.compare(ips[1], ipv6s[1]);
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);        
        exception = false;
        try {
            IPAddressComparator.compare(ipv6masks[1], ipv6s[1]);
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);    }

    public void testAnd() {
        assertTrue(IPAddressComparator.compare(IPAddressComparator.andBytes(new byte[] { 123, 123, 123, 123 },
                new byte[] { -1, -1, 0, 0 }), new byte[] { 123, 123, 0, 0 }));
        assertTrue(IPAddressComparator.compare(IPAddressComparator.andBytes(new byte[] { -1, -1, -1, -1 }, new byte[] {
                -1, -1, -128, 0 }), new byte[] { -1, -1, -128, 0 }));
        assertTrue(IPAddressComparator.compare(IPAddressComparator.andBytes(new byte[] { -1, -1, -1, -1 }, new byte[] {
                -1, -1, -128, 0 }), new byte[] { -1, -1, -128, 0 }));
        assertTrue(IPAddressComparator.compare(IPAddressComparator.andBytes(new byte[] { -1, -1, -1, -1 }, new byte[] {
                -86, -86, -86, -86 }), new byte[] { -86, -86, -86, -86 }));
        assertTrue(IPAddressComparator.compare(IPAddressComparator.andBytes(new byte[] { 85, 85, 85, 85 }, new byte[] {
                -86, -86, -86, -86 }), new byte[] { 0, 0, 0, 0 }));
        assertTrue(IPAddressComparator.compare(IPAddressComparator.andBytes(new byte[] { -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1 }, new byte[] { -1, -1, -1, -1, -1, -1, -128, 0, 0, 0, 0, 0, 0, 0,
                0, 0 }), new byte[] { -1, -1, -1, -1, -1, -1, -128, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
        assertTrue(IPAddressComparator.compare(IPAddressComparator.andBytes(new byte[] { 85, 85, 85, 85, 85, 85, 85,
                85, 85, 85, 85, 85, 85, 85, 85, 85 }, new byte[] { -86, -86, -86, -86, -86, -86, -86, -86, -86, -86,
                -86, -86, -86, -86, -86, -86 }), new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
        boolean exception = false;
        try {
            IPAddressComparator.andBytes(new byte[] { 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85 },
                    new byte[] { -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86 });
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
    }

    public void testCopy() {
        assertTrue(IPAddressComparator.compare(IPAddressComparator.copyBytes(new byte[] { 123, 124, 125, 126 }, 0, 4),
                new byte[] { 123, 124, 125, 126 }));
        assertTrue(IPAddressComparator.compare(IPAddressComparator.copyBytes(new byte[] { 123, 124, 125, 126 }, 0, 3),
                new byte[] { 123, 124, 125 }));
        assertTrue(IPAddressComparator.compare(IPAddressComparator.copyBytes(new byte[] { 123, 124, 125, 126 }, 1, 4),
                new byte[] { 124, 125, 126 }));

    }
    
    public void testParseIP(){
        IPAddressComparator.compare(IPAddressComparator.parseIP("123.124.125.126"), new byte[]{123, 124, 125, 126});
        IPAddressComparator.compare(IPAddressComparator.parseIP("255.255.255.255"), new byte[]{-1, -1, -1, -1});
        IPAddressComparator.compare(IPAddressComparator.parseIP("::1"), new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1});
        IPAddressComparator.compare(IPAddressComparator.parseIP("::123.124.125.126"), new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,123,124,125,126});
        IPAddressComparator.compare(IPAddressComparator.parseIP("FFFF::123.124.125.126"), new byte[]{-1,-1,0,0,0,0,0,0,0,0,0,0,123,124,125,126});
        IPAddressComparator.compare(IPAddressComparator.parseIP("FFFF::123.124.125.126"), new byte[]{-1,-1,0,0,0,0,0,0,0,0,0,0,123,124,125,126});
        IPAddressComparator.compare(IPAddressComparator.parseIP("FFFF::FFFF"), new byte[]{-1,-1,0,0,0,0,0,0,0,0,0,0,0,0,-1,-1});
        IPAddressComparator.compare(IPAddressComparator.parseIP("FFFF:0101:1:7F7F:2:3:4:FFFF"), new byte[]{-1,-1,1,1,0,1,127,127,0,2,0,3,0,4,-1,-1});
        IPAddressComparator.compare(IPAddressComparator.parseIP("FFFF::1:123.124.125.126"), new byte[]{-1,-1,0,0,0,0,0,0,0,0,0,1,123,124,125,126});
     
        // test too many fields
        boolean exception = false;
        try {
            IPAddressComparator.parseIP("123.124.125.126.127");
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
        
        //test too few fields
        exception = false;
        try {
            IPAddressComparator.parseIP("123.300.125");
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
        
        //test too big value
        exception = false;
        try {
            IPAddressComparator.parseIP("123.300.125.126");
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
        
        //test too small value
        exception = false;
        try {
            IPAddressComparator.parseIP("123.-1.125.126");
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
        
        //test invalid value
        exception = false;
        try {
            IPAddressComparator.parseIP("abc");
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);

        // test too many fields
        exception = false;
        try {
            IPAddressComparator.parseIP("::123.124.125.126.127");
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
        
        //test too few fields
        exception = false;
        try {
            IPAddressComparator.parseIP("::123.300.125");
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
        
        //test too big value
        exception = false;
        try {
            IPAddressComparator.parseIP("::123.300.125.126");
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
        
        //test too small value
        exception = false;
        try {
            IPAddressComparator.parseIP("::123.-1.125.126");
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
        
        //test invalid chars
        exception = false;
        try {
            IPAddressComparator.parseIP("::xx");
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);

        //test too many shorthands, only one allowed
        exception = false;
        try {
            IPAddressComparator.parseIP("FFFF::FFFF::FFFF");
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
    }
    
    public void testIsWithinAddressSpace(){
        assertTrue(IPAddressComparator.isWithinAddressSpace(new byte[]{123, 124, 3, 4},new byte[]{123, 124, 125, 126, -1, -1, 0, 0}));
        assertTrue(IPAddressComparator.isWithinAddressSpace(new byte[]{123, 124, 125, 126},new byte[]{123, 124, 125, 126, -1, -1, 0, 0}));
        assertFalse(IPAddressComparator.isWithinAddressSpace(new byte[]{123, 125, 125, 126},new byte[]{123, 124, 125, 126, -1, -1, 0, 0}));
        assertFalse(IPAddressComparator.isWithinAddressSpace(new byte[]{126, 125, 125, 126},new byte[]{123, 124, 125, 126, -1, -1, 0, 0}));
        assertFalse(IPAddressComparator.isWithinAddressSpace(new byte[]{123, 126, 125, 126},new byte[]{123, 124, 125, 126, -1, -1, 0, 0}));
        assertTrue(IPAddressComparator.isWithinAddressSpace(new byte[]{123, 124, 125, 126,0,0, 0,0,8,0, 5,0,0,0, 0,0},new byte[]{123, 124, 125, 126, 0,0, 0,0,0,0, 0,0,0,0, 0,0, -1, -1, 0, 0,0,0, 0,0,0,0, 0,0,0,0, 0,0}));
        assertTrue(IPAddressComparator.isWithinAddressSpace(new byte[]{123, 124, 125, 126,120,121, 122,119,-1,-30, 70,100,64,2, 54,42},new byte[]{123, 124, 125, 126, 120,121, 122,119,1,2, 3,4,5,6, 7,8, -1, -1, -1, -1,-1,-1, -1,-1,0,0, 0,0,0,0, 0,0}));
        assertTrue(IPAddressComparator.isWithinAddressSpace(new byte[]{123, 124, 125, 126,120,121, 122,119,-1,-30, 70,100,64,2, 54,42},new byte[]{123, 124, 125, 126, 120,121, 122,119,1,2, 3,4,5,6, 7,8, -1, -1, -1, -1,-1,-1, -1,-1,0,0, 0,0,0,0, 0,0}));
        assertFalse(IPAddressComparator.isWithinAddressSpace(new byte[]{123, 126, 125, 126,120,121, 122,119,-1,-30, 70,100,64,2, 54,42},new byte[]{123, 124, 125, 126, 120,121, 122,119,1,2, 3,4,5,6, 7,8, -1, -1, -1, -1,-1,-1, -1,-1,0,0, 0,0,0,0, 0,0}));
        assertFalse(IPAddressComparator.isWithinAddressSpace(new byte[]{126, 124, 125, 126,120,121, 122,119,-1,-30, 70,100,64,2, 54,42},new byte[]{123, 124, 125, 126, 120,121, 122,119,1,2, 3,4,5,6, 7,8, -1, -1, -1, -1,-1,-1, -1,-1,0,0, 0,0,0,0, 0,0}));

        // test too many fields
        boolean exception = false;
        try {
            IPAddressComparator.isWithinAddressSpace(new byte[]{123, 124, 3, 4},new byte[]{123, 124, 125, 126, -1, -1, 0, 0, 0});
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
        
        // test too many fields
        exception = false;
        try {
            IPAddressComparator.isWithinAddressSpace(new byte[]{123, 124, 3, 4, 0},new byte[]{123, 124, 125, 126, -1, -1, 0, 0});
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
        
        // test too many fields
        exception = false;
        try {
            IPAddressComparator.isWithinAddressSpace(new byte[]{123, 124, 3, 4},new byte[]{123, 124, 125, 126, 120,121, 122,119,1,2, 3,4,5,6, 7,8, -1, -1, -1, -1,-1,-1, -1,-1,0,0, 0,0,0,0, 0,0});
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
        
        // test too many fields
        exception = false;
        try {
            IPAddressComparator.isWithinAddressSpace(new byte[]{126, 124, 125, 126,120,121, 122,119,-1,-30, 70,100,64,2, 54,42},new byte[]{123, 124, 125, 126, -1, -1, 0, 0});
        } catch (IllegalArgumentException e) {
            exception = true;
        }
        assertTrue(exception);
        
    }

}
