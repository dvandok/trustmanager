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

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;

import junit.framework.Test;
import junit.framework.TestSuite;

import org.glite.security.TestBase;
import org.glite.security.util.CertUtil;
import org.glite.security.util.DNHandler;
import org.glite.security.util.FileCertReader;
import org.glite.security.util.IPAddressComparator;
import org.glite.security.util.Password;
import org.glite.security.util.PrivateKeyReader;

public class ProxyCertificateGeneratorTest extends TestBase {

	public ProxyCertificateGeneratorTest(String arg0) {
		super(arg0);
	}

	public static Test suite() {
		return new TestSuite(ProxyCertificateGeneratorTest.class);
	}

	public void testRFCProxyGen() {
		try {
			// printInterval("Start");
			BufferedInputStream bin = new BufferedInputStream(new FileInputStream(m_certHome + "/home/userkey.pem"));
			// printInterval("inputstream open");
			PrivateKey privateKey = PrivateKeyReader.read(bin, "changeit");
			// printInterval("key read");
			FileCertReader certReader = new FileCertReader();
			// printInterval("setup certreader");
			X509Certificate cert = (X509Certificate) certReader.readCerts(m_certHome + "/home/usercert.pem")
					.firstElement();

			// printInterval("cert read");
			// test rfc 3820 proxy ----------------------------------------------------------------------------------
			ProxyCertificateGenerator rfcProxyGen = new ProxyCertificateGenerator(cert);
			// printInterval();
			rfcProxyGen.setSerialNumber(BigInteger.valueOf(999));
			rfcProxyGen.setProxyPathLimit(5);
			rfcProxyGen.setLimited();
			rfcProxyGen.generate(privateKey);
			// printInterval();
			X509Certificate[] certs = rfcProxyGen.getCertChain();
			PrivateKey key = rfcProxyGen.getPrivateKey();
			assertTrue(certs[1].equals(cert));
			checkChainKey(key, certs);
			assertTrue(DNHandler.getSubject(certs[0]).withoutLastCN(true).equals(DNHandler.getIssuer(certs[0])));
			assertTrue(DNHandler.getSubject(certs[0]).withoutLastCN(true).equals(DNHandler.getSubject(certs[1])));
			ProxyCertificateInfo proxyInfo = new ProxyCertificateInfo(certs[0]);
			ProxyChainInfo proxyChainInfo = new ProxyChainInfo(certs);
			assertTrue(proxyInfo.getProxyType() == ProxyCertificateInfo.RFC3820_PROXY);
			assertTrue(proxyInfo.getProxyPolicyOID().equals(ProxyPolicy.LIMITED_PROXY_OID));
			assertTrue(proxyInfo.getPolicyASN1() == null);
			assertFalse(certs[0].getSerialNumber().equals(certs[1].getSerialNumber()));
			assertTrue(proxyInfo.isLimited());
			assertTrue(proxyInfo.getProxyTracingSubject() == null);
			assertTrue(proxyInfo.getProxyTracingIssuer() == null);
			assertTrue(proxyInfo.getProxyPathLimit() == 5);
			assertTrue(proxyChainInfo.getProxyType() == ProxyCertificateInfo.RFC3820_PROXY);
			String[] tracing = proxyChainInfo.getProxyTracingSubjects();
			for (int i = 0; i < tracing.length; i++) {
				assertTrue(tracing[i] == null);
			}
			tracing = proxyChainInfo.getProxyTracingIssuers();
			for (int i = 0; i < tracing.length; i++) {
				assertTrue(tracing[i] == null);
			}
			assertTrue(proxyChainInfo.getProxyPathLimit() == 5);
			assertTrue(proxyChainInfo.getProxySourceRestrictions() == null);

			// test rfc3820 proxy-proxy
			// ---------------------------------------------------------------------------------------------
			ProxyCertificateGenerator rfcProxyProxyGen = new ProxyCertificateGenerator(rfcProxyGen.getCertChain());
			rfcProxyProxyGen.setProxyTracingSubject("http://home.machine.org/services/testservice");
			rfcProxyProxyGen.setProxyTracingIssuer("gsi-client://home.machine.org/testuser");
			ProxyRestrictionData data = new ProxyRestrictionData();
			data.addPermittedIPAddressWithNetmask("137.138.0.0/16");
			rfcProxyProxyGen.setProxySourceRestrictions(data);
			rfcProxyProxyGen.generate(rfcProxyGen.getPrivateKey());
			certs = rfcProxyProxyGen.getCertChain();
			// FileOutputStream writer = new FileOutputStream("testcert.der");
			// writer.write(certs[0].getEncoded());
			// writer.close();
			assertTrue(certs[1].equals(rfcProxyGen.getCertChain()[0]));
			checkChainKey(rfcProxyProxyGen.getPrivateKey(), certs);
			assertTrue(DNHandler.getSubject(certs[0]).withoutLastCN(true).equals(DNHandler.getIssuer(certs[0])));
			assertTrue(DNHandler.getSubject(certs[0]).withoutLastCN(true).equals(DNHandler.getSubject(certs[1])));
			proxyInfo = new ProxyCertificateInfo(certs[0]);
			System.out.println(certs[0]);
			System.out.println(certs[1]);
			proxyChainInfo = new ProxyChainInfo(certs);
			assertTrue(proxyInfo.getProxyPathLimit() == ProxyCertInfoExtension.UNLIMITED);
			assertTrue(proxyInfo.getProxyPolicyOID() != null);
			assertTrue(proxyInfo.getProxyPolicyOID().equals(ProxyPolicy.INHERITALL_POLICY_OID));
			assertTrue(proxyInfo.getPolicyASN1() == null);
			assertFalse(certs[0].getSerialNumber().equals(certs[1].getSerialNumber()));
			assertFalse(proxyInfo.isLimited());
			assertTrue(proxyInfo.getProxyTracingSubject() != null);
			assertTrue(proxyInfo.getProxyTracingIssuer() != null);
			assertTrue(proxyInfo.getProxyType() == ProxyCertificateInfo.RFC3820_PROXY);
			assertTrue(proxyInfo.getProxyTracingIssuer().equals("gsi-client://home.machine.org/testuser"));
			assertTrue(proxyInfo.getProxyTracingSubject().equals("http://home.machine.org/services/testservice"));
			assertTrue(IPAddressComparator.compare(proxyInfo.getProxySourceRestrictions().getIPSpaces()[0][0],
					IPAddressComparator.parseIP("137.138.0.0/16")));
			assertTrue(proxyInfo.getProxySourceRestrictions().getIPSpaces().length == 2);
			assertTrue(proxyInfo.getProxySourceRestrictions().getIPSpaces()[0].length == 1);
			assertTrue(proxyInfo.getProxySourceRestrictions().getIPSpaces()[1].length == 0);
			assertTrue(proxyInfo.getProxyTargetRestrictions() == null);
			assertTrue(proxyChainInfo.getProxyType() == ProxyCertificateInfo.RFC3820_PROXY);
			tracing = proxyChainInfo.getProxyTracingSubjects();
			for (int i = 0; i < tracing.length; i++) {
				if (i == 2) {
					assertTrue(tracing[i].equals("http://home.machine.org/services/testservice"));
				} else {
					assertTrue(tracing[i] == null);
				}
			}
			tracing = proxyChainInfo.getProxyTracingIssuers();
			for (int i = 0; i < tracing.length; i++) {
				if (i == 2) {
					assertTrue(tracing[i].equals("gsi-client://home.machine.org/testuser"));
				} else {
					assertTrue(tracing[i] == null);
				}
			}
			assertTrue(proxyChainInfo.getProxyPathLimit() == 4);
			byte[][][] restrictions = proxyChainInfo.getProxySourceRestrictions();
			assertTrue(IPAddressComparator.compare(restrictions[0][0], IPAddressComparator.parseIP("137.138.0.0/16")));
			assertTrue(restrictions[1].length == 0);
			assertTrue(restrictions[0].length == 1);
			assertTrue(proxyChainInfo.isLimited());
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (CertificateException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (SignatureException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}

	}

	public void testLegacyProxyGen() {
		try {
			BufferedInputStream bin = new BufferedInputStream(new FileInputStream(m_certHome + "/home/userkey.pem"));
			PrivateKey privateKey = PrivateKeyReader.read(bin, "changeit");
			FileCertReader certReader = new FileCertReader();
			X509Certificate cert = (X509Certificate) certReader.readCerts(m_certHome + "/home/usercert.pem")
					.firstElement();
			// test legacy proxy
			// -------------------------------------------------------------------------------------------
			ProxyCertificateGenerator legacyProxyGen = new ProxyCertificateGenerator(cert);
			legacyProxyGen.setType(ProxyCertificateInfo.LEGACY_PROXY);
			legacyProxyGen.setProxyTracingSubject("http://home.machine.org/services/testservice");
			boolean exception = false;
			try {
				legacyProxyGen.setProxyPathLimit(4);
			} catch (IllegalArgumentException e) {
				exception = true;
			}
			assertTrue(exception);
			ProxyRestrictionData data = new ProxyRestrictionData();
			data.addExcludedIPAddressWithNetmask("137.138.0.0/16");
			legacyProxyGen.setProxyTargetRestrictions(data);
			legacyProxyGen.generate(privateKey);
			X509Certificate[] certs = legacyProxyGen.getCertChain();
			assertTrue(certs[1].equals(cert));
			checkChainKey(legacyProxyGen.getPrivateKey(), certs);
			assertTrue(DNHandler.getSubject(certs[0]).withoutLastCN(true).equals(DNHandler.getIssuer(certs[0])));
			assertTrue(DNHandler.getSubject(certs[0]).withoutLastCN(true).equals(DNHandler.getSubject(certs[1])));
			ProxyCertificateInfo proxyInfo = new ProxyCertificateInfo(certs[0]);
			ProxyChainInfo proxyChainInfo = new ProxyChainInfo(certs);
			assertTrue(proxyInfo.getProxyTracingSubject() != null);
			assertTrue(proxyInfo.getProxyTracingIssuer() == null);
			assertTrue(proxyInfo.getProxyType() == ProxyCertificateInfo.LEGACY_PROXY);
			assertTrue(proxyInfo.getProxyTracingSubject().equals("http://home.machine.org/services/testservice"));
			String[] tracing = proxyChainInfo.getProxyTracingSubjects();
			for (int i = 0; i < tracing.length; i++) {
				if (i == 1) {
					assertTrue(tracing[i].equals("http://home.machine.org/services/testservice"));
				} else {
					assertTrue(tracing[i] == null);
				}
			}
			tracing = proxyChainInfo.getProxyTracingIssuers();
			for (int i = 0; i < tracing.length; i++) {
				assertTrue(tracing[i] == null);
			}
			exception = false;
			try {
				proxyChainInfo.getProxyPathLimit();
			} catch (CertificateException e) {
				exception = true;
			}
			assertTrue(exception);
			byte[][][] restrictions = proxyChainInfo.getProxyTargetRestrictions();
			assertTrue(IPAddressComparator.compare(restrictions[1][0], IPAddressComparator.parseIP("137.138.0.0/16")));
			assertTrue(restrictions[1].length == 1);
			assertTrue(restrictions[0].length == 0);
			assertFalse(proxyChainInfo.isLimited());
			assertTrue(proxyChainInfo.getProxySourceRestrictions() == null);
			for (int n = 0; n < certs.length; n++){
				System.out.println("cert [ " + n + "] " +DNHandler.getSubject(certs[n]).getRFCDN());
			}

			// test legacy proxy-proxy
			// -------------------------------------------------------------------------------------------
			ProxyCertificateGenerator legacyProxyProxyGen = new ProxyCertificateGenerator(legacyProxyGen.getCertChain());
			data = new ProxyRestrictionData();
			data.addExcludedIPAddressWithNetmask("137.138.0.0/16");
			legacyProxyProxyGen.setProxyTargetRestrictions(data);
			legacyProxyProxyGen.setLimited();
			legacyProxyProxyGen.generate(legacyProxyGen.getPrivateKey());
			certs = legacyProxyProxyGen.getCertChain();
			assertTrue(certs[1].equals(legacyProxyGen.getCertChain()[0]));
			checkChainKey(legacyProxyProxyGen.getPrivateKey(), certs);
			proxyInfo = new ProxyCertificateInfo(certs[0]);
			proxyChainInfo = new ProxyChainInfo(certs);
			assertTrue(DNHandler.getSubject(certs[0]).withoutLastCN(true).equals(DNHandler.getIssuer(certs[0])));
			assertTrue(DNHandler.getSubject(certs[0]).withoutLastCN(true).equals(DNHandler.getSubject(certs[1])));
			assertTrue(proxyInfo.getProxyTargetRestrictions() != null);
			assertTrue(proxyInfo.getProxyTargetRestrictions().getIPSpaces().length == 2);
			assertTrue(proxyInfo.getProxyTargetRestrictions().getIPSpaces()[0].length == 0);
			assertTrue(proxyInfo.getProxyTargetRestrictions().getIPSpaces()[1].length == 1);
			assertTrue(proxyInfo.getProxyType() == ProxyCertificateInfo.LEGACY_PROXY);
			assertTrue(IPAddressComparator.compare(proxyInfo.getProxyTargetRestrictions().getIPSpaces()[1][0],
					IPAddressComparator.parseIP("137.138.0.0/16")));
			assertTrue(proxyInfo.getProxySourceRestrictions() == null);
			assertTrue(proxyChainInfo.isLimited());
			assertTrue(proxyInfo.isLimited());

			// test legacy proxy-proxy with extension
			// -------------------------------------------------------------------------------------------
			ProxyCertificateGenerator extLegacyProxyProxyGen = new ProxyCertificateGenerator(
					legacyProxyGen.getCertChain());
			extLegacyProxyProxyGen.setProxyTracingIssuer("gsi-client://home.machine.org/testuser");
			extLegacyProxyProxyGen.generate(legacyProxyGen.getPrivateKey());
			certs = extLegacyProxyProxyGen.getCertChain();
			assertTrue(certs[1].equals(legacyProxyGen.getCertChain()[0]));
			checkChainKey(extLegacyProxyProxyGen.getPrivateKey(), certs);
			assertTrue(DNHandler.getSubject(certs[0]).withoutLastCN(true).equals(DNHandler.getIssuer(certs[0])));
			assertTrue(DNHandler.getSubject(certs[0]).withoutLastCN(true).equals(DNHandler.getSubject(certs[1])));

			proxyInfo = new ProxyCertificateInfo(certs[0]);
			proxyChainInfo = new ProxyChainInfo(certs);
			assertTrue(proxyInfo.getProxyTracingSubject() == null);
			assertTrue(proxyInfo.getProxyTracingIssuer() != null);
			assertTrue(proxyInfo.getProxyTracingIssuer().equals("gsi-client://home.machine.org/testuser"));
			assertFalse(proxyChainInfo.isLimited());
			assertFalse(proxyInfo.isLimited());
			for (int n = 0; n < certs.length; n++){
				System.out.println("cert [ " + n + "] " +DNHandler.getSubject(certs[n]).getRFCDN());
			}

		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (CertificateException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (SignatureException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}

	}

	public void checkChainKey(PrivateKey key, X509Certificate[] certs) {
		X509Certificate proxyCert = certs[0];
		X509Certificate parentCert = certs[1];
		assertTrue(DNHandler.getIssuer(proxyCert).equals(DNHandler.getSubject(parentCert)));

		assertTrue(key.getAlgorithm().equalsIgnoreCase("RSA"));
		assertTrue(key instanceof RSAKey);
		assertTrue(CertUtil.keysMatch(key, proxyCert));

	}

	public void testProxyGen() {
		try {
			BufferedReader br = new BufferedReader(new FileReader(m_certHome + "/trusted-certs/trusted_client.proxy.grid_proxy"));
			PrivateKey privateKey = PrivateKeyReader.read(br);
			FileCertReader certReader = new FileCertReader();
			X509Certificate[] certChain = (X509Certificate[])certReader.readCerts(m_certHome + "/trusted-certs/trusted_client.proxy.grid_proxy").toArray(new X509Certificate[]{});
			// -------------------------------------------------------------------------------------------
			ProxyCertificateGenerator legacyProxyGen = new ProxyCertificateGenerator(certChain);
			legacyProxyGen.generate(privateKey);
			X509Certificate[] certs = legacyProxyGen.getCertChain();
			for (int n = 0; n < certs.length; n++){
				System.out.println("cert [ " + n + "] " +DNHandler.getSubject(certs[n]).getRFCDN());
			}

			ProxyChainInfo proxyChainInfo = new ProxyChainInfo(certs);
			assertTrue(proxyChainInfo.getProxyType() == ProxyCertificateInfo.LEGACY_PROXY);

			// System.out.println(legGenGen.getProxyAsPEM());
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (CertificateException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (SignatureException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}

	}
	
    public void testProxyGenMd5() {
        try {
            BufferedReader br = new BufferedReader(new FileReader(m_certHome + "/trusted-certs/trusted_clientmd5.priv"));
            PrivateKey privateKey = PrivateKeyReader.read(br, new Password("changeit".toCharArray()));
            FileCertReader certReader = new FileCertReader();
            X509Certificate[] certChain = (X509Certificate[])certReader.readCerts(m_certHome + "/trusted-certs/trusted_clientmd5.cert").toArray(new X509Certificate[]{});
            // -------------------------------------------------------------------------------------------
            ProxyCertificateGenerator proxyGen = new ProxyCertificateGenerator(certChain);
            proxyGen.generate(privateKey);
            X509Certificate[] certs = proxyGen.getCertChain();
            System.out.println(certs[0].getSigAlgName());
            assertTrue(certs[0].getSigAlgName().equals(certs[1].getSigAlgName()));

            // System.out.println(legGenGen.getProxyAsPEM());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    
    public void testProxyGenSha224() {
        try {
            BufferedReader br = new BufferedReader(new FileReader(m_certHome + "/trusted-certs/trusted_clientsha224.priv"));
            PrivateKey privateKey = PrivateKeyReader.read(br, new Password("changeit".toCharArray()));
            FileCertReader certReader = new FileCertReader();
            X509Certificate[] certChain = (X509Certificate[])certReader.readCerts(m_certHome + "/trusted-certs/trusted_clientsha224.cert").toArray(new X509Certificate[]{});
            // -------------------------------------------------------------------------------------------
            ProxyCertificateGenerator proxyGen = new ProxyCertificateGenerator(certChain);
            proxyGen.generate(privateKey);
            X509Certificate[] certs = proxyGen.getCertChain();
            System.out.println(certs[0].getSigAlgName());
            assertTrue(certs[0].getSigAlgName().equals(certs[1].getSigAlgName()));

            // System.out.println(legGenGen.getProxyAsPEM());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    
    public void testProxyGenSha256() {
        try {
            BufferedReader br = new BufferedReader(new FileReader(m_certHome + "/trusted-certs/trusted_clientsha256.priv"));
            PrivateKey privateKey = PrivateKeyReader.read(br, new Password("changeit".toCharArray()));
            FileCertReader certReader = new FileCertReader();
            X509Certificate[] certChain = (X509Certificate[])certReader.readCerts(m_certHome + "/trusted-certs/trusted_clientsha256.cert").toArray(new X509Certificate[]{});
            // -------------------------------------------------------------------------------------------
            ProxyCertificateGenerator proxyGen = new ProxyCertificateGenerator(certChain);
            proxyGen.generate(privateKey);
            X509Certificate[] certs = proxyGen.getCertChain();
            System.out.println(certs[0].getSigAlgName());
            assertTrue(certs[0].getSigAlgName().equals(certs[1].getSigAlgName()));

            // System.out.println(legGenGen.getProxyAsPEM());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    
    public void testProxyGenSha384() {
        try {
            BufferedReader br = new BufferedReader(new FileReader(m_certHome + "/trusted-certs/trusted_clientsha384.priv"));
            PrivateKey privateKey = PrivateKeyReader.read(br, new Password("changeit".toCharArray()));
            FileCertReader certReader = new FileCertReader();
            X509Certificate[] certChain = (X509Certificate[])certReader.readCerts(m_certHome + "/trusted-certs/trusted_clientsha384.cert").toArray(new X509Certificate[]{});
            // -------------------------------------------------------------------------------------------
            ProxyCertificateGenerator proxyGen = new ProxyCertificateGenerator(certChain);
            proxyGen.generate(privateKey);
            X509Certificate[] certs = proxyGen.getCertChain();
            System.out.println(certs[0].getSigAlgName());
            assertTrue(certs[0].getSigAlgName().equals(certs[1].getSigAlgName()));

            // System.out.println(legGenGen.getProxyAsPEM());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    
    public void testProxyGenSha512() {
        try {
            BufferedReader br = new BufferedReader(new FileReader(m_certHome + "/trusted-certs/trusted_clientsha512.priv"));
            PrivateKey privateKey = PrivateKeyReader.read(br, new Password("changeit".toCharArray()));
            FileCertReader certReader = new FileCertReader();
            X509Certificate[] certChain = (X509Certificate[])certReader.readCerts(m_certHome + "/trusted-certs/trusted_clientsha512.cert").toArray(new X509Certificate[]{});
            // -------------------------------------------------------------------------------------------
            ProxyCertificateGenerator proxyGen = new ProxyCertificateGenerator(certChain);
            proxyGen.generate(privateKey);
            X509Certificate[] certs = proxyGen.getCertChain();
            System.out.println(certs[0].getSigAlgName());
            assertTrue(certs[0].getSigAlgName().equals(certs[1].getSigAlgName()));

            // System.out.println(legGenGen.getProxyAsPEM());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    
    
}
