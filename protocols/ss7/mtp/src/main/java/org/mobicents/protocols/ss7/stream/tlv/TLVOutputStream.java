/**
 * 
 */
package org.mobicents.protocols.ss7.stream.tlv;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Simple stream to encode data
 * @author baranowb
 *
 */
public class TLVOutputStream extends ByteArrayOutputStream {
	public void writeTag(int tagClass, boolean primitive, long tag) {
		//FIXME: add this
		
	}
	/**
	 * Method used to write tags for common types - be it complex or primitive.
	 * 
	 * @param tagClass
	 * @param primitive
	 * @param value -
	 *            less significant bits(4) are encoded as tag code
	 */
	public void writeTag(int tagClass, boolean primitive, int value) {

		int toEncode = (tagClass & 0x03) << 6;
		toEncode |= (primitive ? 0 : 1) << 5;
		toEncode |= value & 0x1F;
		this.write(toEncode);
	}

	/**
	 * Method used to write tags for common types - be it complex or primitive.
	 * 
	 * @param tagClass
	 * @param primitive
	 * @param value -
	 *            less significant bits(4) are encoded as tag code
	 */
	public void writeTag(int tagClass, boolean primitive, byte[] value) {

		int toEncode = (tagClass & 0x03) << 6;
		toEncode |= (primitive ? 0 : 1) << 5;
		// toEncode |= value & 0x0F;
		// FIXME: add hack here
		this.write(toEncode);
	}

	/**
	 * Writes length in simple or indefinite form
	 * 
	 * @param l
	 */
	public void writeLength(int v) {
		if(v>0x7F)
		{
			//long form
			if ((v & 0xFF000000) > 0) {
				count = 4;
			} else if ((v & 0x00FF0000) > 0) {
				count = 3;
			} else if ((v & 0x0000FF00) > 0) {
				count = 2;
			} else {
				count = 1;
			}
			this.write(count | 0x80);
			this.write((byte)(v>>24));
			this.write((byte)(v>>16));
			this.write((byte)(v>>8));
			this.write((byte)(v));
			
			
			
		}else
		{	//short
			this.write(v & 0xFF);
		}

		
	}
	
	public void writeLinkStatus(LinkStatus ls)
	{
		this.writeTag(Tag.CLASS_APPLICATION, true, Tag._TAG_LINK_STATUS);
		this.writeLength(1);
		this.write(ls.getStatus());
	}
	
	public void writeData(byte[] b) throws IOException
	{
		this.writeTag(Tag.CLASS_APPLICATION, true, Tag._TAG_LINK_DATA);
		this.writeLength(b.length);
		this.write(b);
	}
}
