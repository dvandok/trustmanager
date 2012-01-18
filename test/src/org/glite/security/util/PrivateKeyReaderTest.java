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

import org.bouncycastle.jce.provider.JDKKeyPairGenerator;
import org.bouncycastle.openssl.PasswordFinder;

import org.glite.security.TestBase;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringBufferInputStream;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;


/**
 *
 * Testing the PrivateKeyReader
 *
 * @author  Joni Hahkala
 *
 * Created on September 23, 2002, 10:17 AM
 */
public class PrivateKeyReaderTest extends TestBase {
    /** DOCUMENT ME! */
    static Logger logger = Logger.getLogger(PrivateKeyReaderTest.class.getName());

    /** DOCUMENT ME! */
    protected static final char[] password = "changeit".toCharArray();

    /** DOCUMENT ME! */
    protected static final char[] garbage = "asdf".toCharArray();

    /** DOCUMENT ME! */
    protected BufferedInputStream unencBis;

    /** DOCUMENT ME! */
    protected BufferedInputStream encBis;

    /** Creates a new instance of PrivateKeyReaderTest */
    public PrivateKeyReaderTest(String arg0) throws Exception {
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
        return new TestSuite(PrivateKeyReaderTest.class);
    }

    /**
     * DOCUMENT ME!
     *
     * @throws Throwable DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void atestSkipLine() throws Throwable {
        byte[] buff = new byte[100];

        BufferedInputStream bInputS = new BufferedInputStream(new FileInputStream(m_utilJavaRoot
                    + "/test/input/skiplinetestpattern.txt"));

        bInputS.mark(100);
        bInputS.read(buff);
        bInputS.reset();

        assertTrue((new String(buff)).startsWith("line 1"));

        PrivateKeyReader.skipLine(bInputS);

        bInputS.mark(100);
        bInputS.read(buff);
        bInputS.reset();

        assertTrue((new String(buff)).startsWith("line 2"));

        PrivateKeyReader.skipLine(bInputS);

        bInputS.mark(100);
        bInputS.read(buff);
        bInputS.reset();

        assertTrue((new String(buff)).startsWith("line 3"));

        try {
            PrivateKeyReader.skipLine(bInputS);
        } catch (IOException e) {
            return;
        }

        fail("No exception thrown when end of line reached");
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws IOException DOCUMENT ME!
     */
    protected BufferedInputStream openEnc() throws IOException {
        return openFile(m_certHome + "/trusted-certs/trusted_client.priv");
    }

    /**
     * 
     *
     * @return DOCUMENT ME!
     *
     * @throws IOException DOCUMENT ME!
     */
    protected BufferedInputStream openUnenc() throws IOException {
        return openFile(m_certHome + "/trusted-ca/trusted.priv");
    }

    /**
     * Opens a garbage file, no private key inside.
     *
     * @return DOCUMENT ME!
     *
     * @throws IOException DOCUMENT ME!
     */
    protected BufferedInputStream openGarbage1() throws IOException {
        return openFile(m_certHome + "/trusted-ca/trusted.cert");
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws IOException DOCUMENT ME!
     */
    protected BufferedInputStream openGarbage2() throws IOException {
        return openFile(m_utilJavaRoot
            + "/test/input/skiplinetestpattern.txt");
    }

    /**
     * DOCUMENT ME!
     *
     * @param fileName DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws IOException DOCUMENT ME!
     */
    protected BufferedInputStream openFile(String fileName)
        throws IOException {
        return new BufferedInputStream(new FileInputStream(fileName));
    }

    /**
     * DOCUMENT ME!
     *
     * @throws Throwable DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testRead1() throws Throwable {
        boolean success = false;

        BufferedInputStream file = openUnenc();
        PrivateKeyReader.read(file, new Password(password));
        file.close();

        file = openUnenc();
        PrivateKeyReader.read(file, (PasswordFinder) null);
        file.close();

        file = openUnenc();
        PrivateKeyReader.read(file, new Password(garbage));
        file.close();

        file = openEnc();
        PrivateKeyReader.read(file, new Password(password));
        file.close();

        file = openEnc();

        try {
            PrivateKeyReader.read(file, (PasswordFinder) null);
        } catch (Exception e) {
            success = true;
        }

        assertTrue(success);
        file.close();

        success = false;
        file = openEnc();

        try {
            PrivateKeyReader.read(file, new Password(garbage));
        } catch (Exception e) {
            success = true;
        }

        assertTrue(success);
        file.close();

        success = false;
        file = openGarbage1();

        try {
            PrivateKeyReader.read(file, new Password(password));
        } catch (Exception e) {
            success = true;
        }

        assertTrue(success);
        file.close();

        success = false;
        file = openGarbage2();

        try {
            PrivateKeyReader.read(file, new Password(password));
        } catch (Exception e) {
            success = true;
        }

        assertTrue(success);
        file.close();

        success = false;

        try {
            PrivateKeyReader.read((BufferedInputStream)null, new Password(password));
        } catch (Exception e) {
            success = true;
        }

        assertTrue(success);
    }

    /**
     * DOCUMENT ME!
     *
     * @throws Throwable DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testRead2() throws Throwable {
        boolean success = false;

        BufferedInputStream file = openUnenc();
        PrivateKeyReader.read(file, new String(password));
        file.close();

        file = openUnenc();
        PrivateKeyReader.read(file, (String) null);
        file.close();

        file = openUnenc();
        PrivateKeyReader.read(file, new String(garbage));
        file.close();

        file = openEnc();
        PrivateKeyReader.read(file, new String(password));
        file.close();

        file = openEnc();

        try {
            PrivateKeyReader.read(file, (String) null);
        } catch (Exception e) {
            success = true;
        }

        assertTrue(success);
        file.close();

        success = false;
        file = openEnc();

        try {
            PrivateKeyReader.read(file, new String(garbage));
        } catch (Exception e) {
            success = true;
        }

        assertTrue(success);
        file.close();

        success = false;
        file = openGarbage1();

        try {
            PrivateKeyReader.read(file, new Password(password));
        } catch (Exception e) {
            success = true;
        }

        assertTrue(success);
        file.close();

        success = false;
        file = openGarbage2();

        try {
            PrivateKeyReader.read(file, new Password(password));
        } catch (Exception e) {
            success = true;
        }

        assertTrue(success);
        file.close();

        success = false;

        try {
            PrivateKeyReader.read((BufferedInputStream)null, new Password(password));
        } catch (Exception e) {
            success = true;
        }

        assertTrue(success);
    }

    /**
     * DOCUMENT ME!
     *
     * @throws Throwable DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testRead3() throws Throwable {
        boolean success = false;

        BufferedInputStream file = openUnenc();
        PrivateKeyReader.read(file);
        file.close();

        success = false;
        file = openEnc();

        try {
            PrivateKeyReader.read(file);
        } catch (Exception e) {
            success = true;
        }

        assertTrue(success);
        file.close();

        success = false;

        try {
            PrivateKeyReader.read((BufferedInputStream)null);
        } catch (Exception e) {
            success = true;
        }

        assertTrue(success);
    }
    
    /**
     * Test pkcs8 private key loading.
     *
     * @throws Throwable DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testReadPKCS8() throws Throwable {
        BufferedInputStream file = openFile(m_utilJavaRoot
                + "/test/input/trusted_client.pkcs8.priv");
        PrivateKey key = PrivateKeyReader.read(file);
        file.close();
        assertFalse(key == null);
        BufferedReader reader = new BufferedReader(new FileReader(m_utilJavaRoot
                + "/test/input/trusted_client.pkcs8.priv"));
        key = PrivateKeyReader.read(reader);
        reader.close();
        assertFalse(key == null);
    }

    /**
     * Test pkcs8 private key loading.
     *
     * @throws Throwable DOCUMENT ME!
     */
    @SuppressWarnings("deprecation")
    public void testReadFromProxy() throws Throwable {
        BufferedInputStream file = openFile(m_certHome + "/trusted-certs/trusted_client.proxy.proxy.grid_proxy");
        PrivateKey key = PrivateKeyReader.read(file);
        file.close();
        assertFalse(key == null);
        BufferedReader reader = new BufferedReader(new FileReader(m_certHome + "/trusted-certs/trusted_client.proxy.proxy.grid_proxy"));
        key = PrivateKeyReader.read(reader);
        reader.close();
        assertFalse(key == null);
    }

    /**
     * Test private key writing and loading loading.
     *
     * @throws Throwable DOCUMENT ME!
     */
    public void testWriteRead() throws Throwable {
        JDKKeyPairGenerator.RSA keyPairGen = new JDKKeyPairGenerator.RSA();
        keyPairGen.initialize(1024, new SecureRandom());
        KeyPair pair = keyPairGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        
        String pemKey = PrivateKeyReader.getPEM(privateKey);
    	
        StringReader reader = new StringReader(pemKey);
        
        PrivateKey readKey = PrivateKeyReader.read(new BufferedReader(reader));
        
        assertTrue(readKey.equals(privateKey));
        
        StringBufferInputStream inputStream = new StringBufferInputStream(pemKey);
        
        PrivateKey readKey2 = PrivateKeyReader.read(new BufferedInputStream(inputStream));
        
        assertTrue(readKey2.equals(privateKey));        
    }
}
