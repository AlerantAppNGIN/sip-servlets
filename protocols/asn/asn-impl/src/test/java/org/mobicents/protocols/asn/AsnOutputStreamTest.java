package org.mobicents.protocols.asn;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.BitSet;

import junit.framework.TestCase;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 
 * @author amit bhayani
 * @author baranowb
 */
public class AsnOutputStreamTest extends TestCase {

	private AsnOutputStream output;

	@BeforeClass
	public static void setUpClass() throws Exception {
	}

	@AfterClass
	public static void tearDownClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
		this.output = new AsnOutputStream();
	}

	@After
	public void tearDown() {
		this.output = null;
	}

	private void compareArrays(byte[] expected, byte[] encoded) {
		boolean same = Arrays.equals(expected, encoded);
		assertTrue("byte[] dont match, expected|encoded \n"
				+ Arrays.toString(expected) + "\n" + Arrays.toString(encoded),
				same);
	}

	@Test
	public void testNULL() throws Exception {
		byte[] expected = new byte[] { 0x05, 0 };
		this.output.writeNULL();
		byte[] encodedData = this.output.toByteArray();

		compareArrays(expected, encodedData);
	}

	@Test
	public void testBooleanPos() throws Exception {
		// T L V
		byte[] expected = new byte[] { 0x01, 0x01, (byte) 0xFF };
		this.output.writeBoolean(true);
		byte[] encodedData = this.output.toByteArray();

		compareArrays(expected, encodedData);

	}

	@Test
	public void testBooleanNeg() throws Exception {

		// T L V
		byte[] expected = new byte[] { 0x01, 0x01, 0x00 };
		this.output.writeBoolean(false);
		byte[] encodedData = this.output.toByteArray();

		compareArrays(expected, encodedData);
	}

	@Test
	public void testInteger72() throws Exception {

		byte[] expected = new byte[] { 0x02, 0x01, 0x48 };
		this.output.writeInteger(72);
		byte[] encodedData = this.output.toByteArray();

		compareArrays(expected, encodedData);
	}

	@Test
	public void testInteger127() throws Exception {

		byte[] expected = new byte[] { 0x02, 0x01, 0x7F };
		this.output.writeInteger(127);
		byte[] encodedData = this.output.toByteArray();

		compareArrays(expected, encodedData);
	}

	@Test
	public void testInteger_128() throws Exception {
		// T L V
		byte[] expected = new byte[] { 0x02, 0x01, (byte) 0x80 };
		this.output.writeInteger(-128);
		byte[] encodedData = this.output.toByteArray();

		compareArrays(expected, encodedData);
	}

	@Test
	public void testInteger128() throws Exception {
		// T L V -------------
		byte[] expected = new byte[] { 0x02, 0x02, 0x00, (byte) 0x80 };
		this.output.writeInteger(128);
		byte[] encodedData = this.output.toByteArray();

		compareArrays(expected, encodedData);
	}

	@Test
	public void testRealBinary118_625() throws Exception { // s E M
		// 118.625 ---- 0 10000000101 1101 10101000 00000000 00000000 00000000
		// 00000000 00000000
		// T L V: info bits, exp(2), mantisa(7)
		byte[] expected = new byte[] { 0x09, 0x0A, (byte) 0x81, 0x04, 0x05,
				0x0D, (byte) 0xA8, 0x00, 0x00, 0x00, 0x00, 0x00 };

		this.output.writeReal(118.625d);
		byte[] encoded = this.output.toByteArray();
		compareArrays(expected, encoded);
	}

	@Test
	public void testRealBinary_118_625() throws Exception { // s E M
		// 118.625 ---- 1 10000000101 1101 10101000 00000000 00000000 00000000
		// 00000000 00000000
		// T L V: info bits, exp(2), mantisa(7)
		byte[] expected = new byte[] { 0x09, 0x0A, (byte) (0x81 | 0x40), 0x04,
				0x05, 0x0D, (byte) 0xA8, 0x00, 0x00, 0x00, 0x00, 0x00 };

		this.output.writeReal(-118.625d);
		byte[] encoded = this.output.toByteArray();
		compareArrays(expected, encoded);
	}

	@Test
	public void testRealBinary0() throws Exception {
		// T L V - no V :)
		byte[] expected = new byte[] { 0x09, 0x00 };

		this.output.writeReal(0);
		byte[] encoded = this.output.toByteArray();
		compareArrays(expected, encoded);
	}

	@Test
	public void testRealBinary_NEG_INFINITY() throws Exception {
		// T L V
		byte[] expected = new byte[] { 0x09, 0x01, 0x41 };

		this.output.writeReal(Double.NEGATIVE_INFINITY);
		byte[] encoded = this.output.toByteArray();
		compareArrays(expected, encoded);
	}

	@Test
	public void testRealBinary_POS_INFINITY() throws Exception {
		// T L V
		byte[] expected = new byte[] { 0x09, 0x01, 0x40 };

		this.output.writeReal(Double.POSITIVE_INFINITY);
		byte[] encoded = this.output.toByteArray();
		compareArrays(expected, encoded);
	}

	@Test
	public void testReal10_Basic() throws Exception {
		try {
			this.output.writeReal("3", BERStatics.REAL_NR1 - 1);
			fail();
		} catch (AsnException asne) {

		}
		try {
			this.output.writeReal("3", BERStatics.REAL_NR3 + 1);
			fail();
		} catch (AsnException asne) {

		}
		try {
			this.output.writeReal("x3", BERStatics.REAL_NR3);
			fail();
		} catch (NumberFormatException e) {

		}
		try {
			this.output.writeReal("3x", BERStatics.REAL_NR3);
			fail();
		} catch (NumberFormatException e) {

		}
	}

	@Test
	public void testReal10() throws Exception {
		// we actually dont check NR, its responsibility of other
		// its base10 are encoded as strings... ech, we dont check encoded
		// string... should we?
		String[] digs = new String[] { "   0004902", "  +0004902", " -4902",
				"4902.00", "4902.", ".5", " 0.3E-04", "-2.8E+000000",
				"   000004.50000E123456789", "+5.6e+03", "+0.56E+4" };

		for (int index = 0; index < digs.length; index++) {
			double d = Double.parseDouble(digs[index]);
			// NR should change, but its responsiblity of user.
			this.output.writeReal(digs[index], BERStatics.REAL_NR1);
			byte[] encoded = this.output.toByteArray();
			// this will "clear" array.
			this.output.reset();

			AsnInputStream asnIs = new AsnInputStream(new ByteArrayInputStream(
					encoded));
			asnIs.readTag();
			double dd = asnIs.readReal();
			assertEquals("Decoded value is not proper!!", d, dd);
		}

	}

	@Test
	public void testBinaryString_Short() throws Exception {
		// 11110000 11110000 111101xx //0x0F accoring to book...
		byte[] expected = new byte[] { 0x03, 0x04, 0x02, (byte) 0xF0,
				(byte) 0xF0, (byte) 0xF4 };
		BitSet bs = new BitSet();
		bs.set(0);
		bs.set(1);
		bs.set(2);
		bs.set(3);
		bs.set(8);
		bs.set(9);
		bs.set(10);
		bs.set(11);
		bs.set(16);
		bs.set(17);
		bs.set(18);
		bs.set(19);
		bs.set(21);
		this.output.writeStringBinary(bs);
		byte[] encoded = this.output.toByteArray();
		compareArrays(expected, encoded);
	}

	@Test
	public void testBinaryString_Complex() throws Exception {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		byte[] expected = new byte[] { 0x03, 0x04, 0x02, (byte) 0xF0,
				(byte) 0xF0, (byte) 0xF4 };
		BitSet bs = new BitSet();
		// complex start
		bos.write(0x03 | (0x01 << 5));
		bos.write(0x80);

		// primitive start
		bos.write(0x03);
		bos.write(0x7F);

		// extra octet
		bos.write(0x00);
		for (int i = 0; i < 126; i++) {
			if (i % 2 == 0) {
				bos.write(0x0A);
				// 0000 1010
				bs.set(i * 8 + 4);
				bs.set(i * 8 + 6);
			} else {
				bos.write(0x0F);
				bs.set(i * 8 + 4);
				bs.set(i * 8 + 5);
				bs.set(i * 8 + 6);
				bs.set(i * 8 + 7);
			}
		}

		// next primitive
		bos.write(expected);

		// terminate complex
		bos.write(0x00);
		bos.write(0x00);

		bs.set(126 * 8 + 0);
		bs.set(126 * 8 + 1);
		bs.set(126 * 8 + 2);
		bs.set(126 * 8 + 3);
		bs.set(126 * 8 + 8);
		bs.set(126 * 8 + 9);
		bs.set(126 * 8 + 10);
		bs.set(126 * 8 + 11);
		bs.set(126 * 8 + 16);
		bs.set(126 * 8 + 17);
		bs.set(126 * 8 + 18);
		bs.set(126 * 8 + 19);
		bs.set(126 * 8 + 21);
		this.output.writeStringBinary(bs);
		byte[] encoded = this.output.toByteArray();
		compareArrays(bos.toByteArray(), encoded);
	}

	@Test
	public void testUTF8StringShort() throws Exception {
		String dataString = "ACEace$} - S�u�by wiedz�, kto zorganizowa� zamachy w metrze.";
		byte[] data = dataString.getBytes(BERStatics.STRING_UTF8_ENCODING);
		ByteArrayOutputStream bos = new ByteArrayOutputStream(10);
		// write tag
		bos.write((Tag.CLASS_UNIVERSAL << 6) | (Tag.PC_PRIMITIVITE << 5)
				| Tag.STRING_UTF8);
		bos.write(data.length);
		bos.write(data);

		byte[] expected = bos.toByteArray();

		this.output.writeStringUTF8(dataString);
		byte[] encoded = this.output.toByteArray();
		compareArrays(expected, encoded);
	}

	@Test
	public void testUTF8StringComplex() throws Exception {
		// actual encoding of this is 80bytes, double == 160
		//commenting out, it fails on linux
		String dataString = "ACEace$} - Sluzby wiedza, kto zorganizowal zamachy w metrze.";
		dataString += dataString+dataString;
		dataString = dataString.substring(0,160);
		byte[] data = dataString.getBytes(BERStatics.STRING_UTF8_ENCODING);
		ByteArrayOutputStream bos = new ByteArrayOutputStream(10);
		// write tag
		bos.write((Tag.CLASS_UNIVERSAL << 6) | (Tag.PC_CONSTRUCTED << 5)
				| Tag.STRING_UTF8);
		bos.write(0x80);

		bos.write((Tag.CLASS_UNIVERSAL << 6) | (Tag.PC_PRIMITIVITE << 5)
				| Tag.STRING_UTF8);
		bos.write(127);
		bos.write(data, 0, 127);
		bos.write((Tag.CLASS_UNIVERSAL << 6) | (Tag.PC_PRIMITIVITE << 5)
				| Tag.STRING_UTF8);
		bos.write(160 - 127);
		bos.write(data, 127, 160 - 127);

		bos.write(0);
		bos.write(0);

		byte[] expected = bos.toByteArray();

		this.output.writeStringUTF8(dataString);
		byte[] encoded = this.output.toByteArray();
		compareArrays(expected, encoded);
	}

	@Test
	public void testIA5StringShort() throws Exception {
		String dataString = "ACEace$}";
		byte[] data = dataString.getBytes(BERStatics.STRING_IA5_ENCODING);
		ByteArrayOutputStream bos = new ByteArrayOutputStream(10);
		// write tag
		bos.write((Tag.CLASS_UNIVERSAL << 6) | (Tag.PC_PRIMITIVITE << 5)
				| Tag.STRING_IA5);
		bos.write(data.length);
		bos.write(data);

		byte[] expected = bos.toByteArray();

		this.output.writeStringIA5(dataString);
		byte[] encoded = this.output.toByteArray();
		compareArrays(expected, encoded);
	}

	@Test
	public void testIA5StringComplex() throws Exception {
		// actual encoding of this is 80bytes, double == 160
		String dataString = "ACEace$}ACEace$}ACEace$}ACEace$}ACEace$}ACEace$}ACEace$}ACEace$}ACEace$}ACEace$}ACEace$}";
		dataString += dataString;

		byte[] data = dataString.getBytes(BERStatics.STRING_IA5_ENCODING);

		ByteArrayOutputStream bos = new ByteArrayOutputStream(10);
		// write tag
		bos.write((Tag.CLASS_UNIVERSAL << 6) | (Tag.PC_CONSTRUCTED << 5)
				| Tag.STRING_IA5);
		bos.write(0x80);

		bos.write((Tag.CLASS_UNIVERSAL << 6) | (Tag.PC_PRIMITIVITE << 5)
				| Tag.STRING_IA5);
		bos.write(127);
		bos.write(data, 0, 127);
		bos.write((Tag.CLASS_UNIVERSAL << 6) | (Tag.PC_PRIMITIVITE << 5)
				| Tag.STRING_IA5);
		bos.write(176 - 127);
		bos.write(data, 127, 176 - 127);

		bos.write(0);
		bos.write(0);

		byte[] expected = bos.toByteArray();

		this.output.writeStringIA5(dataString);
		byte[] encoded = this.output.toByteArray();
		compareArrays(expected, encoded);
	}
	
	@Test
	public void testObjectIdentifier() throws Exception {
		
		byte[] expected = new byte[] {Tag.OBJECT_IDENTIFIER, 0x6, 0x4, 0x28, (byte) 0xC2, (byte) 0x7B, 0x02 };
		
		long[] oids = new long[]{1, 0, 8571, 2};

		// Tag
		this.output.write(Tag.OBJECT_IDENTIFIER);
		
		//Length and Value
		this.output.writeObjectIdentifier(oids);
		
		byte[] encodedData = this.output.toByteArray();
		
		compareArrays(expected, encodedData);
	}	

}
