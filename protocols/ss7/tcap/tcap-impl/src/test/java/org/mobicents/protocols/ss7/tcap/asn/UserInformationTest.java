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

package org.mobicents.protocols.ss7.tcap.asn;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;

import junit.framework.TestCase;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;

public class UserInformationTest extends TestCase {

	@org.junit.Test
	public void testUserInformationDecode() throws IOException, AsnException {

		// This raw data is from wireshark trace of TCAP - MAP
		byte[] data = new byte[] { (byte) 0xbe, 0x25, 0x28, 0x23, 0x06, 0x07,
				0x04, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, (byte) 0xa0, 0x18,
				(byte) 0xa0, (byte) 0x80, (byte) 0x80, 0x09, (byte) 0x96, 0x02,
				0x24, (byte) 0x80, 0x03, 0x00, (byte) 0x80, 0x00, (byte) 0xf2,
				(byte) 0x81, 0x07, (byte) 0x91, 0x13, 0x26, (byte) 0x98,
				(byte) 0x86, 0x03, (byte) 0xf0, 0x00, 0x00 };

		AsnInputStream asin = new AsnInputStream(new ByteArrayInputStream(data));
		int tag = asin.readTag();
		assertEquals(UserInformation._TAG, tag);

		UserInformation userInformation = new UserInformationImpl();
		userInformation.decode(asin);
		
		assertTrue(userInformation.isOid());
		
		assertTrue(Arrays.equals(new long[] { 0, 4, 0, 0, 1, 1, 1, 1 },
				userInformation.getOidValue()));

		assertFalse(userInformation.isInteger());

		assertTrue(userInformation.isAsn());
		assertTrue(Arrays.equals(new byte[] { (byte) 0xa0, (byte) 0x80,
				(byte) 0x80, 0x09, (byte) 0x96, 0x02, 0x24, (byte) 0x80, 0x03,
				0x00, (byte) 0x80, 0x00, (byte) 0xf2, (byte) 0x81, 0x07,
				(byte) 0x91, 0x13, 0x26, (byte) 0x98, (byte) 0x86, 0x03,
				(byte) 0xf0, 0x00, 0x00 }, userInformation.getEncodeType()));


	}
	

	//@org.junit.Test
	public void testUserInformationEncode() throws IOException, ParseException {
		
		byte[] encodedData = new byte[] { (byte) 0xbe, 0x25, 0x28, 0x23, 0x06, 0x07,
				0x04, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, (byte) 0xa0, 0x18,
				(byte) 0xa0, (byte) 0x80, (byte) 0x80, 0x09, (byte) 0x96, 0x02,
				0x24, (byte) 0x80, 0x03, 0x00, (byte) 0x80, 0x00, (byte) 0xf2,
				(byte) 0x81, 0x07, (byte) 0x91, 0x13, 0x26, (byte) 0x98,
				(byte) 0x86, 0x03, (byte) 0xf0, 0x00, 0x00 };		
		
		
		UserInformation userInformation = new UserInformationImpl();

		
		
		userInformation.setOid(true);
		userInformation.setOidValue(new long[] { 0, 4, 0, 0, 1, 1, 1, 1 });

		userInformation.setAsn(true);
		userInformation.setEncodeType(new byte[] { (byte) 0xa0, (byte) 0x80,
				(byte) 0x80, 0x09, (byte) 0x96, 0x02, 0x24, (byte) 0x80, 0x03,
				0x00, (byte) 0x80, 0x00, (byte) 0xf2, (byte) 0x81, 0x07,
				(byte) 0x91, 0x13, 0x26, (byte) 0x98, (byte) 0x86, 0x03,
				(byte) 0xf0, 0x00, 0x00 });		
		
		
		AsnOutputStream asnos = new AsnOutputStream();
		userInformation.encode(asnos);
		
		byte[] userInfData = asnos.toByteArray();
		
		String s = TcBeginTest.dump(userInfData, userInfData.length, false);
		assertTrue(Arrays.equals(encodedData, userInfData));
		
		
		
	}

}
