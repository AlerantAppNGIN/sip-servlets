/*
 * JBoss, Home of Professional Open Source
 * Copyright 2011, Red Hat, Inc. and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

/*
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.mobicents.servlet.sip.testsuite.proxy;

import javax.sip.ListeningPoint;

import org.mobicents.servlet.sip.SipServletTestCase;

public class ParallelProxyWithRecordRouteTest extends SipServletTestCase {

	protected Shootist shootist;

	protected Shootme shootme;
	
	protected Cutme cutme;

	private static final int TIMEOUT = 10000;
	private static final int TIMEOUT_READY_TO_INVALIDTE = 70000;

	public ParallelProxyWithRecordRouteTest(String name) {
		super(name);

		this.sipIpAddress="0.0.0.0";
		startTomcatOnStartup = false;
		autoDeployOnStartup = false;
	}

	@Override
	public void setUp() throws Exception {
		super.setUp();
		tomcat.addSipConnector(serverName, sipIpAddress, 5070, ListeningPoint.TCP);
		tomcat.startTomcat();
		deployApplication();
		this.shootist = new Shootist(false);
		shootist.setOutboundProxy(false);
		this.shootme = new Shootme(5057);
		this.cutme = new Cutme();
	}
	
	public void testProxyCalleeSendsBye() {
		this.shootme.init("stackName", null);
		this.shootme.callerSendsBye = false;
		try {
		this.cutme.init(null);
		this.shootist.init("useHostName",false, null);
		for (int q = 0; q < 20; q++) {
			if (shootist.ended == false && cutme.canceled == false)
				try {
					Thread.sleep(TIMEOUT);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}
		} catch(Exception e) {}
		this.shootme.callerSendsBye = true;
		if (shootist.ended == false)
			fail("Conversation not complete!");
		if (cutme.canceled == false)
			fail("The party that was supposed to be cancelled didn't cancel.");
	}
	

	public void testProxy() {
		this.shootme.init("stackName", null);
		this.cutme.init(null);
		this.shootist.init("useHostName",false, null);
		for (int q = 0; q < 20; q++) {
			if (shootist.ended == false && cutme.canceled == false)
				try {
					Thread.sleep(TIMEOUT);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}
		if (shootist.ended == false)
			fail("Conversation not complete!");
		if (cutme.canceled == false)
			fail("The party that was supposed to be cancelled didn't cancel.");
	}
	
	public void testProxyReadyToInvalidate() {
		this.shootme.init("stackName", null);
		this.cutme.init(null);
		this.shootist.init("check_rti",false, null);
		for (int q = 0; q < 20; q++) {
			if (shootist.ended == false && cutme.canceled == false)
				try {
					Thread.sleep(TIMEOUT_READY_TO_INVALIDTE);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}
		if (shootist.ended == false)
			fail("Conversation not complete!");
		if (cutme.canceled == false)
			fail("The party that was supposed to be cancelled didn't cancel.");
		assertNotNull(shootist.getLastMessageContent());	
		assertEquals("sessionReadyToInvalidate", shootist.getLastMessageContent());
	}
	
	public void testProxyReadyToInvalidateTCP() {
		this.shootme.init("stackName", "tcp");
		this.cutme.init("tcp");
		this.shootist.init("check_rti",false, "tcp");
		for (int q = 0; q < 20; q++) {
			if (shootist.ended == false && cutme.canceled == false)
				try {
					Thread.sleep(TIMEOUT_READY_TO_INVALIDTE);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}
		if (shootist.ended == false)
			fail("Conversation not complete!");
		if (cutme.canceled == false)
			fail("The party that was supposed to be cancelled didn't cancel.");
		assertNotNull(shootist.getLastMessageContent());	
		assertEquals("sessionReadyToInvalidate", shootist.getLastMessageContent());
	}
	
	/**
	 * Non regression test for  Issue 747 : Non Record Routing Proxy is adding Record Route on informational response
	 * http://code.google.com/p/mobicents/issues/detail?id=747
	 */
	public void testProxyNonRecordRouting() {
		this.shootme.init("stackName", null);
		this.cutme.init(null);
		this.shootist.init("nonRecordRouting",false, null);
		for (int q = 0; q < 20; q++) {
			if (shootist.ended == false && cutme.canceled == false)
				try {
					Thread.sleep(TIMEOUT);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}
		if (shootist.ended == false)
			fail("Conversation not complete!");
		if (cutme.canceled == false)
			fail("The party that was supposed to be cancelled didn't cancel.");
	}
	
	/**
	 * Non regression test for Issue 851 : NPE on handling URI parameters in address headers
	 * http://code.google.com/p/mobicents/issues/detail?id=851
	 */
	public void testProxyURIParams() {
		this.shootme.init("stackName", null);
		this.cutme.init(null);
		this.shootist.init("check_uri",false, null);
		for (int q = 0; q < 20; q++) {
			if (shootist.ended == false && cutme.canceled == false)
				try {
					Thread.sleep(TIMEOUT);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}
		if (shootist.ended == false)
			fail("Conversation not complete!");		
	}

	@Override
	public void tearDown() throws Exception {
		shootist.destroy();
		shootme.destroy();
		cutme.destroy();
		super.tearDown();
	}

	@Override
	public void deployApplication() {
		assertTrue(tomcat
				.deployContext(
						projectHome
								+ "/sip-servlets-test-suite/applications/proxy-sip-servlet/src/main/sipapp",
						"sip-test-context", "sip-test"));
	}

	@Override
	protected String getDarConfigurationFile() {
		return "file:///"
				+ projectHome
				+ "/sip-servlets-test-suite/testsuite/src/test/resources/"
				+ "org/mobicents/servlet/sip/testsuite/proxy/simple-sip-servlet-dar.properties";
	}
}
