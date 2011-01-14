/**
 * 
 */
package org.mobicents.protocols.ss7.tcap.asn;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.ss7.tcap.asn.comp.Parameter;

/**
 * @author baranowb
 * 
 */
public class ParameterImpl implements Parameter {

	private byte[] data;
	private Parameter[] parameters;
	private boolean primitive = true;
	private int tag;
	private int tagClass;

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.tcap.asn.comp.Parameter#getData()
	 */
	public byte[] getData() {

		return data;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.tcap.asn.comp.Parameter#isPrimitive()
	 */
	public boolean isPrimitive() {

		return primitive;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.tcap.asn.comp.Parameter#setData(byte[])
	 */
	public void setData(byte[] b) {
		this.data = b;
		if (data != null)
			this.setParameters(null);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.tcap.asn.comp.Parameter#setPrimitive(boolean)
	 */
	public void setPrimitive(boolean b) {
		if (this.parameters != null && b) {
			// bad
			throw new IllegalArgumentException("Can not set primitive flag since Parameter[] is present!");
		}
		this.primitive = b;
	}

	/**
	 * @return the tag
	 */
	public int getTag() {
		return tag;
	}

	/**
	 * @param tag
	 *            the tag to set
	 */
	public void setTag(int tag) {
		this.tag = tag;
	}

	/**
	 * @return the tagClass
	 */
	public int getTagClass() {
		return tagClass;
	}

	/**
	 * @param tagClass
	 *            the tagClass to set
	 */
	public void setTagClass(int tagClass) {
		this.tagClass = tagClass;
	}

	public Parameter[] getParameters() {

		if (this.parameters == null && !this.isPrimitive()) {
			// we may want to decode
			if (this.data == null) {
				return this.parameters;
			}
			List<Parameter> paramsList = new ArrayList<Parameter>();
			// else we try to decode :)
			try {
				AsnInputStream ais = new AsnInputStream(new ByteArrayInputStream(this.data));
				while (ais.available() > 0) {
					int tag = ais.readTag();
					Parameter _p = TcapFactory.createParameter(tag, ais);
					paramsList.add(_p);

				}

				this.parameters = new Parameter[paramsList.size()];
				this.parameters = paramsList.toArray(this.parameters);
			} catch (Exception e) {
				throw new IllegalArgumentException("Failed to parse raw data into constrcuted parameter", e);
			}
		}
		return this.parameters;
	}

	public void setParameters(Parameter[] paramss) {
		this.parameters = paramss;
		if (this.parameters != null) {
			this.setData(null);
			this.setPrimitive(false);
		}

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
			primitive = ais.isTagPrimitive();
			tagClass = ais.getTagClass();
			int len;

			len = ais.readLength();

			if (len == 0x80) {
				throw new ParseException("Undefined length is not supported.");
			}
			data = new byte[len];
			int tlen = ais.read(data);
			if (tlen != len) {
				throw new ParseException("Not enough data read, expected: " + len + ", actaul: " + tlen);
			}

		} catch (IOException e) {
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
		if (data == null && parameters == null) {
			throw new ParseException("Parameter data not set.");
		}

		aos.writeTag(tagClass, primitive, tag);
		if (data == null) {

			AsnOutputStream localAos = new AsnOutputStream();
			for (Parameter p : this.parameters) {
				p.encode(localAos);
			}
			data = localAos.toByteArray();
		}
		
		try {
			aos.writeLength(data.length);
			aos.write(data);
		} catch (IOException e) {
			throw new ParseException(e);
		}
	}

}
