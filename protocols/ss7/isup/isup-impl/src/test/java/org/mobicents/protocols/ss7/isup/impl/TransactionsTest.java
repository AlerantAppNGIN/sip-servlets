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

package org.mobicents.protocols.ss7.isup.impl;

import java.util.Properties;

import junit.framework.TestCase;

import org.mobicents.protocols.ss7.isup.ISUPStack;
import org.mobicents.protocols.ss7.mtp.pipe.PipeMtpProviderImpl;


public class TransactionsTest extends TestCase {

	private PipeMtpProviderImpl provider1;
	private PipeMtpProviderImpl provider2;
	private ISUPStack isupStack1;
	private ISUPStack isupStack2;
	
	
	
	
	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() throws Exception {
		super.setUp();
		
		this.provider1 = new PipeMtpProviderImpl();
		this.provider2= this.provider1.getOther();
		Properties props1 = new Properties(); 
        Properties props2 = new Properties();
        this.isupStack1 = new ISUPStackImpl(this.provider1, props1);
        this.isupStack2 = new ISUPStackImpl(this.provider2, props2);
		
        
        this.isupStack1.start();
        this.isupStack2.start();
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() throws Exception {
		// TODO Auto-generated method stub
		super.tearDown();
		this.isupStack1.stop();
        this.isupStack2.stop();
		//this.provider1.stop();
		//this.provider2.stop();
		this.provider1 = null;
		this.provider2 = null;
	}

//	public void testIAM() throws Exception
//	{
//		
//		ClientIAM client = new ClientIAM(this.isupStack1);
//		ServerIAM server = new ServerIAM(this.isupStack2);
//		this.isupStack1.getIsupProvider().addListener(client);
//		this.isupStack2.getIsupProvider().addListener(server);
//		provider1.indicateLinkUp();
//		provider2.indicateLinkUp();
//		
//		
//		
//		server.start();
//		client.start();
//		
//		
//		Thread.currentThread().sleep(10000);
//		
//		assertTrue("Client status: "+client.getStatus(),client.isPassed());
//		assertTrue("Server status: "+server.getStatus(),server.isPassed());
//		
//		
//	}
//	
//	public void testREL() throws Exception
//	{
//		
//		ClientREL client = new ClientREL(this.isupStack1);
//		ServerREL server = new ServerREL(this.isupStack2);
//		this.isupStack1.getIsupProvider().addListener(client);
//		this.isupStack2.getIsupProvider().addListener(server);
//		provider1.indicateLinkUp();
//		provider2.indicateLinkUp();
//		
//		
//		
//		server.start();
//		client.start();
//		
//		
//		Thread.currentThread().sleep(10000);
//		
//		assertTrue("Client status: "+client.getStatus(),client.isPassed());
//		assertTrue("Server status: "+server.getStatus(),server.isPassed());
//		
//		
//	}
//	public void testGRS() throws Exception
//	{
//		
//		ClientGRS client = new ClientGRS(this.isupStack1);
//		ServerGRS server = new ServerGRS(this.isupStack2);
//		this.isupStack1.getIsupProvider().addListener(client);
//		this.isupStack2.getIsupProvider().addListener(server);
//		provider1.indicateLinkUp();
//		provider2.indicateLinkUp();
//		
//		
//		
//		server.start();
//		client.start();
//		
//		
//		Thread.currentThread().sleep(10000);
//		
//		assertTrue("Client status: "+client.getStatus(),client.isPassed());
//		assertTrue("Server status: "+server.getStatus(),server.isPassed());
//		
//		
//	}
	public void testX()
	{
		//
	}
}
