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

/**
 * 
 */
package org.mobicents.protocols.ss7.tcap.asn;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.ss7.tcap.asn.comp.Component;
import org.mobicents.protocols.ss7.tcap.asn.comp.TCUniMessage;

/**
 * @author baranowb
 * 
 */
public class TCUniMessageImpl implements TCUniMessage {

	private DialogPortion dp;
	private Component[] component;

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.tcap.asn.comp.TCUniMessage#getComponent()
	 */
	public Component[] getComponent() {

		return component;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.tcap.asn.comp.TCUniMessage#getDialogPortion()
	 */
	public DialogPortion getDialogPortion() {

		return dp;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.tcap.asn.comp.TCUniMessage#setComponent(org
	 * .mobicents.protocols.ss7.tcap.asn.comp.Component[])
	 */
	public void setComponent(Component[] c) {
		this.component = c;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.tcap.asn.comp.TCUniMessage#setDialogPortion
	 * (org.mobicents.protocols.ss7.tcap.asn.DialogPortion)
	 */
	public void setDialogPortion(DialogPortion dp) {
		this.dp = dp;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.tcap.asn.Encodable#decode(org.mobicents.protocols
	 * .asn.AsnInputStream)
	 */
	public void decode(AsnInputStream ais) throws ParseException {
		try {
			int len = ais.readLength();
			if (len > ais.available()) {
				throw new ParseException("Not enough data: " + ais.available());
			}
			if (len == 0x80) {
				//
				throw new ParseException("Undefined len not supported");
			}
			byte[] data = new byte[len];
			if(len!=ais.read(data))
			{
				throw new ParseException("Not enough data read.");
			}
			AsnInputStream localAis = new AsnInputStream(new ByteArrayInputStream(data));

			int tag = localAis.readTag();
			if (tag != DialogPortion._TAG) {
				// we have DP, optional part
				this.dp = TcapFactory.createDialogPortion(localAis);
				tag = localAis.readTag();
			}
			if (tag != Component._COMPONENT_TAG) {
				throw new ParseException("Expected ComponentPortion tag, found: " + tag);
			}
			len = localAis.readLength();
			if (len < localAis.available() || len == 0) {
				throw new ParseException("Not enough data");
			}
			List<Component> cps = new ArrayList<Component>();
			// its iterator :)
			while (localAis.available() > 0) {
				Component c = TcapFactory.createComponent(localAis);
				if(c == null)
				{
					break;
				}
				cps.add(c);
			}

			this.component = new Component[cps.size()];
			this.component = cps.toArray(this.component);
		} catch (IOException e) {
			throw new ParseException(e);
		} catch (AsnException e) {
			throw new ParseException(e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.tcap.asn.Encodable#encode(org.mobicents.protocols
	 * .asn.AsnOutputStream)
	 */
	public void encode(AsnOutputStream aos) throws ParseException {
		if (this.component == null || this.component.length == 0) {
			throw new ParseException("Component portion is mandatory.");
		}
		try {
			AsnOutputStream localAos = new AsnOutputStream();
			byte[] data = null;
			if (this.component != null) {
				for (Component c : this.component) {
					c.encode(localAos);
				}
				data = localAos.toByteArray();
				localAos.reset();
				localAos.writeTag(Component._COMPONENT_TAG_CLASS, Component._COMPONENT_TAG_PC_PRIMITIVE, Component._COMPONENT_TAG);
				localAos.writeLength(data.length);

				localAos.write(data);

				data = localAos.toByteArray();
				localAos.reset();
			}
			if (this.dp != null) {
				this.dp.encode(localAos);
				if(data!=null)
				{
					localAos.write(data);
				}
				data = localAos.toByteArray();
			}else
			{
				if(data!=null)
				{
					localAos.write(data);
				}
				data = localAos.toByteArray();
			}

			aos.writeTag(_TAG_CLASS, _TAG_PC_PRIMITIVE, _TAG);
			aos.writeLength(data.length);
			aos.write(data);
		} catch (IOException e) {
			throw new ParseException(e);
		}

	}

}
