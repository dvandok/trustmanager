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

package org.glite.security.trustmanager;

import junit.framework.TestSuite;

import org.apache.log4j.Logger;

import org.glite.security.TestBase;
import org.glite.security.util.FileCertReader;
import org.glite.security.util.PrivateKeyReader;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;

import java.net.SocketException;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import java.util.Properties;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
//import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Functional unit tests for the ContextWrapper.
 * 
 * @author Joni Hahkala Created on October 21, 2002, 5:28 PM
 */
public class ContextWrapperFuncOpensslTest extends TestBase {
	/** The logging facility. */
	static final Logger LOGGER = Logger.getLogger(ContextWrapperFuncOpensslTest.class.getName());

	/** The port the test servers starts on. */
	int m_port = 11444;

	/** The server socket factory of the test server. */
	private SSLServerSocket m_server = null;

	/** The server thread. */
	private Runner m_runner = null;

	/** The error encountered when starting the server. */
	String m_serverStartError = null;

	/** Whether the server was supposed to accept or not the test. */
	private boolean m_expectedServerOK = true;

	/** Creates a new instance of ContextWrapperTest */
	public ContextWrapperFuncOpensslTest(java.lang.String testName) {
		super(testName);
	}

	/**
	 * A way to run the tests from command line.
	 * 
	 * @param args should be empty.
	 */
	public static void main(java.lang.String[] args) {
		junit.textui.TestRunner.run(suite());
	}

	/**
	 * Returns the automatically generated tests from the "test" methods.
	 * 
	 * @return Returns the automatically generated tests from the "test" methods.
	 */
	public static TestSuite suite() {
		TestSuite suite = new TestSuite(ContextWrapperFuncOpensslTest.class);

		return suite;
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @throws Exception DOCUMENT ME!
	 */
	public void testAuthServer() throws Exception {
		try {
			// setup server
			Properties serverProps = new Properties();
			serverProps.setProperty(ContextWrapper.TRUSTSTORE_DIR, m_certHome + "/grid-security/certificates");
			serverProps.setProperty(ContextWrapper.CREDENTIALS_CERT_FILE, m_certHome
					+ "/trusted-certs/trusted_server.cert");
			serverProps.setProperty(ContextWrapper.CREDENTIALS_KEY_FILE, m_certHome
					+ "/trusted-certs/trusted_server.priv");
			serverProps.setProperty(ContextWrapper.CREDENTIALS_KEY_PASSWD, "changeit");

			Runner serverThread = new Runner(this, serverProps, m_port);
			serverThread.start();

			// setup client stuff
			Properties baseProps = new Properties();
			baseProps.setProperty(ContextWrapper.TRUSTSTORE_DIR, m_certHome + "/grid-security/certificates");
			baseProps.setProperty(ContextWrapper.CRL_ENABLED, "true");
			baseProps.setProperty(ContextWrapper.CRL_REQUIRED, "true");

			OpensslCertPathValidatorTest proxyTest = new OpensslCertPathValidatorTest("test");
			proxyTest.setup(false);

			// wait server to start
			getServer(true);

			// do tests
            doTests(baseProps, proxyTest.m_bigProxies, false, m_port);
            doTests(baseProps, proxyTest.m_subsubBadDNProxies, false, m_port);
            doTests(baseProps, proxyTest.m_subsubRevokedProxies, false, m_port);
            doTests(baseProps, proxyTest.m_subsubProxies, false, m_port);
            doTests(baseProps, proxyTest.m_trustedCerts, false, m_port);
			doTests(baseProps, proxyTest.m_trustedRevokedCerts, false, m_port);
			doTests(baseProps, proxyTest.m_trustedProxies, false, m_port);
			doTests(baseProps, proxyTest.m_trustedRevokedProxies, false, m_port);
			doTests(baseProps, proxyTest.m_fakeCerts, false, m_port);
			doTests(baseProps, proxyTest.m_fakeProxies, false, m_port);
			doTests(baseProps, proxyTest.m_miscProxies, false, m_port);

			m_runner.closeServer();

			getServer(false);
		} catch (Exception e) {
			if (m_runner != null) {
				m_runner.closeServer();
			}

			throw e;
		}
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @throws Exception DOCUMENT ME!
	 */
	public void tearDown() throws Exception {
		if (m_runner != null) {
			m_runner.closeServer();
		}
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @param baseProps DOCUMENT ME!
	 * @param testItems DOCUMENT ME!
	 * @param reverse DOCUMENT ME!
	 * @param port DOCUMENT ME!
	 * @throws Exception DOCUMENT ME!
	 */
	public void doTests(Properties baseProps, OpensslCertPathValidatorTest.TestItem[] testItems, boolean reverse, int port)
			throws Exception {
		int n;

		for (n = 0; n < testItems.length; n++) {
			doTest(baseProps, testItems[n], reverse, port);
			doTestInternal(baseProps, testItems[n], reverse, port);
		}
	}

	/**
	 * test using normal properties based contextwrapper setup
	 */
	public void doTest(Properties baseProps, OpensslCertPathValidatorTest.TestItem testItem, boolean reverse, int port)
			throws Exception {
		boolean exception = reverse;
		LOGGER.debug("testing: " + testItem.m_fileName);

		try {
			Properties props = new Properties(baseProps);

			if (testItem.m_proxy == true) {
				props.setProperty(ContextWrapper.CREDENTIALS_PROXY_FILE, testItem.m_fileName);
			} else {
				props.setProperty(ContextWrapper.CREDENTIALS_CERT_FILE, testItem.m_fileName + ".cert");
				props.setProperty(ContextWrapper.CREDENTIALS_KEY_FILE, testItem.m_fileName + ".priv");
				props.setProperty(ContextWrapper.CREDENTIALS_KEY_PASSWD, "changeit");

				// for testing only, override the expiration checking during the cert loading to be able to load expired
				// certs to test rejection at server end.
				props.setProperty(ContextWrapper.OVERRIDE_EXPIRATION_CHECK_ON_INIT, "true");
			}

			if ((testItem.m_ok && !reverse) || (!testItem.m_ok && reverse)) {
				m_expectedServerOK = true;
			} else {
				m_expectedServerOK = false;
			}

			SSLContextWrapper wrapper = ContextFactory.createContextWrapper(props);

			doClientTest(wrapper, port);
		} catch (Exception e) {
			exception = !reverse;

			if (testItem.m_ok != reverse) {
				LOGGER.error("Error while testing " + testItem.m_fileName
						+ " Exception occured while it was not suppose to occur. File was: " + testItem.m_fileName
						+ ".cert. Message was " + e.getMessage());
				e.printStackTrace(System.err);
				fail("Error while testing " + testItem.m_fileName
						+ " Exception occured while it was not suppose to occur. File was: " + testItem.m_fileName
						+ ".cert. Message was " + e.getMessage());
			}
		}

		if (testItem.m_ok == exception) {
			LOGGER.error("Error while testing " + testItem.m_fileName
					+ " No exception occured when one was expected. File was: " + testItem.m_fileName + ".cert");
			fail("Error while testing " + testItem.m_fileName
					+ " No exception occured when one was expected. File was: " + testItem.m_fileName + ".cert");
		}
	}

	/**
	 * test using given cert chain and key
	 */
	@SuppressWarnings("unchecked")
	public void doTestInternal(Properties baseProps, OpensslCertPathValidatorTest.TestItem testItem, boolean reverse,
			int port) throws Exception {
		boolean exception = reverse;
		LOGGER.debug("testing: " + testItem.m_fileName);

		try {
			FileCertReader fileCertReader = new FileCertReader();

			Properties props = new Properties(baseProps);
			X509Certificate[] chain = null;
			PrivateKey key = null;

			if (testItem.m_proxy == true) {
				KeyStore proxyStore = fileCertReader.readProxy(new BufferedInputStream(new FileInputStream(
						testItem.m_fileName)), "changeit");
				String alias = proxyStore.aliases().nextElement();

				chain = (X509Certificate[]) proxyStore.getCertificateChain(alias);
				key = (PrivateKey) proxyStore.getKey(alias, "changeit".toCharArray());
			} else {
				chain = (X509Certificate[]) (fileCertReader.readCerts(testItem.m_fileName + ".cert")
						.toArray(new X509Certificate[] {}));
				key = PrivateKeyReader.read(
						new BufferedInputStream(new FileInputStream(testItem.m_fileName + ".priv")), "changeit");
			}

			if ((testItem.m_ok && !reverse) || (!testItem.m_ok && reverse)) {
				m_expectedServerOK = true;
			} else {
				m_expectedServerOK = false;
			}

			ContextWrapper wrapper = new ContextWrapper(props, chain, key);
			doClientTest(wrapper, port);
		} catch (Exception e) {
			exception = !reverse;

			if (testItem.m_ok == exception) {
				LOGGER.error("Error while testing "
						+ testItem.m_fileName
						+ (testItem.m_ok ? " Exception occured while it was not suppose to occure "
								: " No exception occured when one was expected"));
				throw e;
			}
		}

		if (testItem.m_ok == exception) {
			LOGGER.error("Error while testing "
					+ testItem.m_fileName
					+ (testItem.m_ok ? " Exception occured while it was not suppose to occure "
							: " No exception occured when one was expected"));
		}

		assertTrue(testItem.m_ok != exception);
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @param wrapper DOCUMENT ME!
	 * @param port DOCUMENT ME!
	 * @throws Exception DOCUMENT ME!
	 */
	public void doClientTest(SSLContextWrapper wrapper, int port) throws Exception {
		try {
			SSLSocket socket = (SSLSocket) wrapper.getSocketFactory().createSocket("localhost", port);

			// System.out.println("Connecting plain http server");
			OutputStream out = socket.getOutputStream();

			String host = socket.getInetAddress().getCanonicalHostName();
//			SSLSession session = socket.getSession();

			// java.security.cert.Certificate array[] = session.getPeerCertificates();
			// List list = Arrays.asList(array);
			// Iterator iter = list.listIterator();
			// while(iter.hasNext()){
			// System.out.println("server cert is " + iter.next());
			// }
			// System.out.println("Host: " + host);
			// out.write("GET /examples/servlet/ContextTestServlet HTTP/1.1\n".getBytes());
			// out.write("GET /index.html HTTP/1.1\n".getBytes());
			out.write("GET /index.html HTTP/1.1\n".getBytes());

			// out.write("GET-TEST /index.html HTTP/1.1\n".getBytes());
			out.write(("Host: " + host + "\n\n").getBytes());
			out.flush();

			// out.close();
			// ///////////////////////////////////////////////////////////
			// get path to class file from header
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			String buf;
			buf = in.readLine();

			while (buf != null) {
				// System.out.println("> " + buf);
				buf = in.readLine();
			}

			in.close();
		} catch (Exception e) {
			LOGGER.debug("connection failed: " + e.getMessage());
			throw e;
		}
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @param exist DOCUMENT ME!
	 * @return DOCUMENT ME!
	 * @throws Exception DOCUMENT ME!
	 */
	public synchronized SSLServerSocket getServer(boolean exist) throws Exception {
		if (exist) {
			while (m_server == null) {
				try {
					wait();
				} catch (InterruptedException e) {
					//don't care
				}

				if (m_serverStartError != null) {
					throw new Exception("Failed to start server. Error was: " + m_serverStartError);
				}
			}
		} else {
			while (m_server != null) {
				try {
					wait();
				} catch (InterruptedException e) {
					//don't care
				}
			}
		}

		return m_server;
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @param server DOCUMENT ME!
	 * @param thread DOCUMENT ME!
	 */
	public synchronized void setServer(SSLServerSocket server, Runner thread) {
		this.m_server = server;
		m_runner = thread;
		notifyAll();
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @param serverProps DOCUMENT ME!
	 * @param port DOCUMENT ME!
	 * @return DOCUMENT ME!
	 * @throws Exception DOCUMENT ME!
	 */
	public SSLServerSocket getServerSocket(Properties serverProps, int port) throws Exception {
		SSLContextWrapper wrapper = ContextFactory.createContextWrapper(serverProps);
		SSLServerSocketFactory factory = wrapper.getServerSocketFactory();

		return (SSLServerSocket) factory.createServerSocket(port);
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @param sSocket DOCUMENT ME!
	 */
	public void handleServer(SSLServerSocket sSocket) {
		SSLSocket socket;
		boolean serving = true;

		// sSocket.setWantClientAuth(true);
		sSocket.setNeedClientAuth(true);

		do {
			try {
				socket = (SSLSocket) sSocket.accept();

				DataOutputStream out = new DataOutputStream(socket.getOutputStream());

				try {
					BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
					String buf;

					buf = in.readLine();

					if (!buf.equals("GET /index.html HTTP/1.1")) {
						throw new Exception("invalid input from client");
					}

					while (buf != null) {
						// System.out.println("> " + buf);
						if (buf.length() <= 0) {
							break;
						}

						buf = in.readLine();
					}

					try {
						out.writeBytes("HTTP/1.0 200 OK\r\n");
						out.writeBytes("Content-Type: text/html\r\n\r\n\r\n");
						out.writeBytes("TEST OK\r\n");
						out.flush();
						out.close();
					} catch (IOException ie) {
//						ie.printStackTrace();
						throw ie;
					}
				} catch (Exception e) {
					// e.printStackTrace();
					// write out error response, if possible
					out.writeBytes("HTTP/1.0 400 " + e.getMessage() + "\r\n");
					out.writeBytes("Content-Type: text/html\r\n\r\n");
					out.flush();
					out.close();
					throw e;
				}
			} catch (SocketException ex) {
				// eat exception
				LOGGER.debug("Socket closed?: " + ex.getMessage());

				// ex.printStackTrace();
				serving = false;
			} catch (Exception ex) {
				// write error message if error was unexpected
				if (m_expectedServerOK) {
					LOGGER.error("error writing response: " + ex.getMessage());
					ex.printStackTrace();
				}
			}
		} while (serving == true);
	}

	/**
	 * DOCUMENT ME!
	 * 
	 * @author Joni Hahkala <joni.hahkala@cern.ch>
	 */
	public class Runner extends Thread {
		/** DOCUMENT ME! */
		ContextWrapperFuncOpensslTest parent;

		/** DOCUMENT ME! */
		Properties props;

		/** DOCUMENT ME! */
		int port;

		/** DOCUMENT ME! */
		SSLServerSocket serverSocket;

		/**
		 * Creates a new Runner object.
		 * 
		 * @param testClass DOCUMENT ME!
		 * @param serverProps DOCUMENT ME!
		 * @param port DOCUMENT ME!
		 */
		public Runner(ContextWrapperFuncOpensslTest testClass, Properties serverProps, int port) {
			super();
			parent = testClass;
			props = serverProps;
			this.port = port;
		}

		/**
		 * DOCUMENT ME!
		 */
		public void run() {
			try {
				serverSocket = parent.getServerSocket(props, port);
				parent.setServer(serverSocket, this);
				parent.handleServer(serverSocket);
				parent.setServer(null, null);
			} catch (Exception e) {
				LOGGER.error("Error while starting test server. \"Address already in use\" means that there is something alredy running in test server port "
								+ this.parent.m_port + ". The error was: " + e.getMessage());
				parent.m_serverStartError = e.getMessage();
				parent.setServer(null, null);
			}
		}

		/**
		 * DOCUMENT ME!
		 * 
		 * @throws IOException DOCUMENT ME!
		 */
		public void closeServer() throws IOException {
			serverSocket.close();
		}
	}
}
