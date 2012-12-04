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
 * Start time:13:59:51 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 * 
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public interface RedirectStatus extends ISUPParameter {
	public static final int _PARAMETER_CODE = 0x8A;

	/**
	 * See Q.763 3.98 Redirect status indicator : not used
	 */
	public static int _RSI_NOT_USED = 0;
	/**
	 * See Q.763 3.98 Redirect status indicator : ack of redirection
	 */
	public static int _RSI_AOR = 1;
	/**
	 * See Q.763 3.98 Redirect status indicator : redirection will not be
	 * invoked
	 */
	public static int _RSI_RWNBI = 2;

	public byte[] getStatus();

	public void setStatus(byte[] status);

	public int getStatusIndicator(byte b);
}
