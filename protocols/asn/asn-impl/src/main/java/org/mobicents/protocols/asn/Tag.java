package org.mobicents.protocols.asn;

/**
 * 
 * @author amit bhayani
 * @author baranowb
 */
public class Tag {
	
	/**
	 * Class of tag used with primitives
	 */
	public static final int CLASS_UNIVERSAL = 0x0;
	public static final int CLASS_APPLICATION = 0x1;
	public static final int CLASS_CONTEXT_SPECIFIC = 0x2;
	public static final int CLASS_PRIVATE = 0x3;

	// first two bits encode the class
	public static final int CLASS_MASK = 0xC0;

	// The next bit (bit six) is called the primitive/constructed (P/C) bit
	public static final int PC_MASK = 0x20;
	public static final int PC_PRIMITIVITE = 0x0;
	public static final int PC_CONSTRUCTED = 0x1;

	// The last five bits (bits 5 to 1) encode the number of the tag in tag octet
	public static final int TAG_MASK = 0x1F;

	// Universal class tag assignments as per X.680-0207, Section 8.4
	public static final int BOOLEAN = 0x01;
	public static final int INTEGER = 0x02;
	public static final int STRING_BIT = 0x03;
	public static final int STRING_OCTET = 0x04;
	public static final int NULL = 0x05;
    public static final int OBJECT_IDENTIFIER = 0x06;
    public static final int EXTERNAL = 0x8;
	public static final int REAL = 0x09;
	public static final int ENUMERATED = 0x0A;
	public static final int STRING_UTF8 = 0x0C;
	public static final int SEQUENCE = 0x10; 
	public static final int STRING_IA5 = 0x16;
	//UNKNOWN, add this ....
	public static final int OBJECT_DESCRIPTOR = 0xFF;
	
	//values for ending stream of string for constructed form, see 18.2.6 in ASN.1 Communication between Heterogeneous Systems
	public static final int NULL_TAG = 0x00;
	public static final int NULL_VALUE = 0x00;
	

	private Tag() {
		super();
	
	}


	public static boolean isPrimitive(int tagValue)
	{
		//no shift needed, since for primitive its '0'
		return (tagValue & PC_MASK) == PC_PRIMITIVITE;
	}

	public static int getSimpleTagValue(int tagValue)
	{
		return tagValue & TAG_MASK;
	}
	public static boolean isUniversal(int tagValue)
	{
		return (tagValue & CLASS_MASK) == CLASS_UNIVERSAL;
	}
}
