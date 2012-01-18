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

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;

import org.glite.security.TestBase;

import junit.framework.Test;
import junit.framework.TestSuite;

/**
 * @author hahkala
 */
public class TrustStorageTest extends TestBase {
    // number of test CAs
    static final int VALID_CA_NUMBER = 8;
    
    /**
     * @param arg0
     */
    public TrustStorageTest(String arg0) {
        super(arg0);
        // TODO Auto-generated constructor stub
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
        return new TestSuite(TrustStorageTest.class);
    }

    @SuppressWarnings("deprecation")
    public void testLoad() throws Exception {
        TrustStorage storage = new TrustStorage(m_certHome + "/grid-security/certificates-withnamespaceerrors");
        @SuppressWarnings("unused")
        FullTrustAnchor[] anchors = storage.getAnchors();
        TrustStorage storage2 = new TrustStorage(m_certHome + "/grid-security/certificates-withoutCrl");
        @SuppressWarnings("unused")
        FullTrustAnchor[] anchors2 = storage2.getAnchors();
        // for(FullTrustAnchor anchor:anchors){
        // System.out.println(anchor);
        // }
    }

    @SuppressWarnings("deprecation")
    public void testUpdate() throws Exception {
        // create test directory
        java.io.File testDir = new File(m_certHome + "/grid-security/certificates-test");
        try {
            testDir.mkdir();
            File sourceDir = new File(m_certHome + "/grid-security/certificates");
            File sourceFiles[] = sourceDir.listFiles();
            for(File sourceFile: sourceFiles){
                // skip CVS dir
                if(sourceFile.isDirectory()){
                    continue;
                }
                File newFile = new File(testDir, sourceFile.getName());
                FileReader reader = new FileReader(sourceFile);
                FileWriter writer = new FileWriter(newFile);
                char buffer[] = new char[10000];
                int chars;
                while((chars = reader.read(buffer)) > 0){
                    writer.write(buffer, 0, chars);
                }
                reader.close();
                writer.close();
            }
            
            File files[] = testDir.listFiles();
            for(File file:files){
                System.out.println(file.getCanonicalFile());
            }
            System.out.println(testDir.getCanonicalPath());
            TrustStorage storage = new TrustStorage(testDir.getCanonicalPath());
            FullTrustAnchor[] anchors = storage.getAnchors();
            int n = anchors.length;
            
            //delete one ca
            File delFile = new File(testDir, "2ed6e90e.0");
            delFile.delete();
            storage.checkUpdate();
            
            // check that one ca disappeared when it was removed
            assertTrue(n == storage.getAnchors().length + 1);

            // put file back
            FileReader reader = new FileReader(sourceDir.getCanonicalFile() + "/2ed6e90e.0");
            FileWriter writer = new FileWriter(testDir.getCanonicalFile() + "/2ed6e90e.0");
            char buffer[] = new char[10000];
            int chars;
            while((chars = reader.read(buffer)) > 0){
                writer.write(buffer, 0, chars);
            }
            reader.close();
            writer.close();
            
            storage.checkUpdate();
            
            // check that one ca was reloaded when it was put back
            assertTrue(n == storage.getAnchors().length);
            
//            files = testDir.listFiles();
//            for(File file:files){
//                System.out.println(file.getName());
//            }
        } finally {
            File files[] = testDir.listFiles();
            for(File file:files){
                file.delete();
            }
            testDir.delete();
        }
    }
    
    @SuppressWarnings("deprecation")
    public void testUpdate2() throws Exception {
    	System.out.println("---------------------------------");
        TrustStorage storage = new TrustStorage(m_certHome + "/grid-security/certificates-withnamespaceerrors");
        FullTrustAnchor[] anchors = storage.getAnchors();
        System.out.println(anchors.length);
        assertTrue(anchors.length == VALID_CA_NUMBER);
        storage.checkUpdate();
        assertTrue(storage.getAnchors().length == VALID_CA_NUMBER);
        storage.checkUpdate();
        storage.checkUpdate();
        storage.checkUpdate();
        storage.checkUpdate();
        assertTrue(storage.getAnchors().length == VALID_CA_NUMBER);
      
        storage = new TrustStorage(m_certHome + "/grid-security/certificates-withoutCrl");
        anchors = storage.getAnchors();
        assertTrue(anchors.length == VALID_CA_NUMBER);
        storage.checkUpdate();
        assertTrue(storage.getAnchors().length == VALID_CA_NUMBER);
        
        storage = new TrustStorage(m_certHome + "/grid-security/certificates");
        anchors = storage.getAnchors();
        assertTrue(anchors.length == VALID_CA_NUMBER);
        storage.checkUpdate();
        assertTrue(storage.getAnchors().length == VALID_CA_NUMBER);
        
        storage = new TrustStorage(m_certHome + "/grid-security/certificates-rootallowsubsubdeny");
        anchors = storage.getAnchors();
        assertTrue(anchors.length == VALID_CA_NUMBER);
        storage.checkUpdate();
        assertTrue(storage.getAnchors().length == VALID_CA_NUMBER);
        
        storage = new TrustStorage(m_certHome + "/grid-security/certificates-subcawithpolicy");
        anchors = storage.getAnchors();
        assertTrue(anchors.length == VALID_CA_NUMBER);
        storage.checkUpdate();
        assertTrue(storage.getAnchors().length == VALID_CA_NUMBER);
        
        storage = new TrustStorage(m_certHome + "/grid-security/certificates-rootwithpolicy");
        anchors = storage.getAnchors();
        assertTrue(anchors.length == VALID_CA_NUMBER);
        storage.checkUpdate();
        assertTrue(storage.getAnchors().length == VALID_CA_NUMBER);
        
        storage = new TrustStorage(m_certHome + "/grid-security/certificates-withoutroot");
        anchors = storage.getAnchors();
        assertTrue(anchors.length == VALID_CA_NUMBER - 1);
        storage.checkUpdate();
        assertTrue(storage.getAnchors().length == VALID_CA_NUMBER - 1);
    }
    
}
