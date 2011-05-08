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

package org.mobicents.protocols.ss7.isup.impl.message.parameter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.mobicents.protocols.ss7.isup.ParameterRangeInvalidException;
import org.mobicents.protocols.ss7.isup.message.parameter.GVNSUserGroup;

/**
 * Start time:13:58:48 2009-04-04<br>
 * Project: mobicents-isup-stack<br>
 * 
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski
 *         </a>
 */
public class GVNSUserGroupImpl extends AbstractNumber implements GVNSUserGroup{

	
	// FIXME: shoudl we add max octets ?
	private int gugLengthIndicator;

	public GVNSUserGroupImpl() {

	}

	public GVNSUserGroupImpl(byte[] representation) throws ParameterRangeInvalidException {
		super(representation);
		
	}

	public GVNSUserGroupImpl(ByteArrayInputStream bis) throws ParameterRangeInvalidException {
		super(bis);
		
	}

	public GVNSUserGroupImpl(String address) {
		super(address);
		
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.isup.ISUPComponent#decodeElement(byte[])
	 */
	public int decodeElement(byte[] b) throws ParameterRangeInvalidException {
		return super.decodeElement(b);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.isup.ISUPComponent#encodeElement()
	 */
	public byte[] encodeElement() throws IOException {
		return super.encodeElement();
	}

	@Override
	public int decodeHeader(ByteArrayInputStream bis) throws IllegalArgumentException {
		int b = bis.read() & 0xff;

		this.oddFlag = (b & 0x80) >> 7;
		this.gugLengthIndicator = b & 0x0F;
		return 1;
	}

	@Override
	public int encodeHeader(ByteArrayOutputStream bos) {
		int b = 0;
		// Even is 000000000 == 0
		boolean isOdd = this.oddFlag == _FLAG_ODD;
		if (isOdd)
			b |= 0x80;
		b |= this.gugLengthIndicator & 0x0F;
		bos.write(b);
		return 1;
	}

	@Override
	public int decodeBody(ByteArrayInputStream bis) throws IllegalArgumentException {

		return 0;
	}

	@Override
	public int encodeBody(ByteArrayOutputStream bos) {

		return 0;
	}

	public int getGugLengthIndicator() {
		return gugLengthIndicator;
	}

	@Override
	public int decodeDigits(ByteArrayInputStream bis) throws IllegalArgumentException, ParameterRangeInvalidException {
		return super.decodeDigits(bis, this.gugLengthIndicator);
	}

	@Override
	public void setAddress(String address) {
		// TODO Auto-generated method stub
		super.setAddress(address);
		int l = super.address.length();
		this.gugLengthIndicator = l / 2 + l % 2;
		if (gugLengthIndicator > 8) {
			throw new IllegalArgumentException("Maximum octets for this parameter in digits part is 8.");
			// FIXME: add check for digit (max 7 ?)
		}
	}

	public int getCode() {

		return _PARAMETER_CODE;
	}
}
