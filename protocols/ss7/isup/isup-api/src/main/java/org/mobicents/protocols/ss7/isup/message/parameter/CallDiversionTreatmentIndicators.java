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

package org.mobicents.protocols.ss7.isup.message.parameter;

/**
 * Start time:11:09:03 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 * 
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public interface CallDiversionTreatmentIndicators extends ISUPParameter {
	public static final int _PARAMETER_CODE = 0x6E;
	/**
	 * See Q.763 3.72 Call to be diverted indicator : no indication
	 */
	public static final int _NO_INDICATION = 0;

	/**
	 * See Q.763 3.72 Call to be diverted indicator : call diversion allowed
	 */
	public static final int _CD_ALLOWED = 1;

	/**
	 * See Q.763 3.72 Call to be diverted indicator : call diversion not allowed
	 */
	public static final int _CD_NOT_ALLOWED = 2;

	public byte[] getCallDivertedIndicators();

	public void setCallDivertedIndicators(byte[] callDivertedIndicators);

	public int getDiversionIndicator(byte b);
}
