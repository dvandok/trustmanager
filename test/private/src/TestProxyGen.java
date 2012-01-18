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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringBufferInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.glite.security.util.FileCertReader;
import org.glite.security.util.PrivateKeyReader;
import org.glite.security.util.proxy.ProxyCertificateGenerator;
import org.glite.security.util.proxy.ProxyCertificateInfo;

public class TestProxyGen {

    /**
     * @param path
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidKeyException
     */
    public static void test(String path) throws IOException, CertificateException, InvalidKeyException,
            SignatureException, NoSuchAlgorithmException {
        FileInputStream bin = new FileInputStream(path + File.separator + "userkey.pem");
        PrivateKey privateKey = PrivateKeyReader.read(new BufferedInputStream(bin), new PromptPasswordFinder());
        FileCertReader certReader = new FileCertReader();
        X509Certificate cert = (X509Certificate) certReader.readCerts(path + File.separator + "usercert.pem")
                .firstElement();

        ProxyCertificateGenerator gen = new ProxyCertificateGenerator(cert);
        gen.setSerialNumber(BigInteger.valueOf(999));        
        gen.generate(privateKey);
        X509Certificate[] certs = gen.getCertChain();
        System.out.println(certs[0].toString());
        

        String keyPEM = gen.getPrivateKeyAsPEM();
        System.out.println(keyPEM);
        System.out.println(gen.getProxyAsPEM());
        
        ProxyCertificateGenerator genGen = new ProxyCertificateGenerator(gen.getCertChain());
        genGen.generate(gen.getPrivateKey());
        certs = genGen.getCertChain();
        System.out.println(certs[0].toString());
        System.out.println(genGen.getProxyAsPEM());
        
        ProxyCertificateGenerator legGen = new ProxyCertificateGenerator(cert);
        legGen.setType(ProxyCertificateInfo.LEGACY_PROXY);
        legGen.generate(privateKey);
        certs = legGen.getCertChain();
        System.out.println(certs[0].toString());
        System.out.println(legGen.getProxyAsPEM());

        ProxyCertificateGenerator legGenGen = new ProxyCertificateGenerator(legGen.getCertChain());
        legGenGen.generate(legGen.getPrivateKey());
        certs = legGenGen.getCertChain();
        System.out.println(certs[0].toString());
        System.out.println(legGenGen.getProxyAsPEM());
    }

}
