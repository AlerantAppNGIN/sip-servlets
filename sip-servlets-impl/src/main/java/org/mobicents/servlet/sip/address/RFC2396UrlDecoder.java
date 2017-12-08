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

package org.mobicents.servlet.sip.address;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.BitSet;

import org.apache.log4j.Logger;

/**
 * Copied from Apache Excalibur project.
 * Source code available at http://www.google.com/codesearch?hl=en&q=+excalibur+decodePath+show:sK_gDY0W5Rw:OTjCHAiSuF0:th3BdHtpX20&sa=N&cd=1&ct=rc&cs_p=http://apache.edgescape.com/excalibur/excalibur-sourceresolve/source/excalibur-sourceresolve-1.1-src.zip&cs_f=excalibur-sourceresolve-1.1/src/java/org/apache/excalibur/source/SourceUtil.java
 * @author <A HREF="mailto:jean.deruelle@gmail.com">Jean Deruelle</A> 
 *
 */
public class RFC2396UrlDecoder {

	private final static Logger logger = Logger.getLogger(RFC2396UrlDecoder.class.getCanonicalName());

	private static final String UTF_8 = "UTF-8";
	private static final int CHARACTER_CASE_DIFF = ('a' - 'A');
	
	// RFC 3261 rules:
	
	private static final BitSet RFC3261_ALPHA;
	static {
		RFC3261_ALPHA = new BitSet();
		int i;
		for (i = 'a'; i <= 'z'; i++) {
			RFC3261_ALPHA.set(i);
		}
		for (i = 'A'; i <= 'Z'; i++) {
			RFC3261_ALPHA.set(i);
		}
	}
	
	private static final BitSet RFC3261_DIGIT;
	static {
		RFC3261_DIGIT = new BitSet();
		for (int i = '0'; i <= '9'; i++) {
			RFC3261_DIGIT.set(i);
		}
	}

	private static final BitSet RFC3261_MARK;
	static {
		RFC3261_MARK = new BitSet();
		for (int j : Arrays.asList('-', '_', '.', '!', '~', '*', '\'', '(', ')')) {
			RFC3261_MARK.set(j);
		}
	}

	// unreserved = ALPHA / DIGIT / mark
	private static final BitSet RFC3261_UNRESERVED;
	static {
		RFC3261_UNRESERVED = new BitSet();
		RFC3261_UNRESERVED.or(RFC3261_ALPHA);
		RFC3261_UNRESERVED.or(RFC3261_DIGIT);
		RFC3261_UNRESERVED.or(RFC3261_MARK);
	}
	
	// hnv-unreserved  =  "[" / "]" / "/" / "?" / ":" / "+" / "$"
	private static final BitSet RFC3261_HNV_UNRESERVED;
	static {
		RFC3261_HNV_UNRESERVED = new BitSet();
		for (int j : Arrays.asList('[', ']', '/', '?', ':', '+', '$')) {
			RFC3261_HNV_UNRESERVED.set(j);
		}
	}
	
	// headers         =  "?" header *( "&" header )
	// header          =  hname "=" hvalue
	// hname           =  1*( hnv-unreserved / unreserved / escaped )
	// hvalue          =  *( hnv-unreserved / unreserved / escaped )
	private static final BitSet RFC3261_HNAME_HVALUE;
	static {
		RFC3261_HNAME_HVALUE = new BitSet();
		RFC3261_HNAME_HVALUE.or(RFC3261_HNV_UNRESERVED);
		RFC3261_HNAME_HVALUE.or(RFC3261_UNRESERVED);
	}
	
	// param-unreserved  =  "[" / "]" / "/" / ":" / "&" / "+" / "$"
	private static final BitSet RFC3261_PARAM_UNRESERVED;
	static {
		RFC3261_PARAM_UNRESERVED = new BitSet(); 
		for (int j : Arrays.asList('[', ']', '/', ':', '&', '+', '$')) {
			RFC3261_PARAM_UNRESERVED.set(j);
		}
	}
	
	// paramchar         =  param-unreserved / unreserved / escaped
	private static final BitSet RFC3261_PARAMCHAR;
	static {
		RFC3261_PARAMCHAR = new BitSet();
		RFC3261_PARAMCHAR.or(RFC3261_PARAM_UNRESERVED);
		RFC3261_PARAMCHAR.or(RFC3261_UNRESERVED);
	}
	
	// other-param       =  pname [ "=" pvalue ]
	// pname			 =	1*paramchar
	// pvalue			 =	1*paramchar
	// Note: separated only for consistency in naming, in case paramchar is referenced from another definition later
	private static final BitSet RFC3261_PNAME_PVALUE = RFC3261_PARAMCHAR;
	

//   RFC3966 (tel URI) parameter rules:
//			   parameter            = ";" pname ["=" pvalue ]
//			   pname                = 1*( alphanum / "-" )
//			   pvalue               = 1*paramchar
//			   paramchar            = param-unreserved / unreserved / pct-encoded
//			   unreserved           = alphanum / mark
//			   mark                 = "-" / "_" / "." / "!" / "~" / "*" /
//			                          "'" / "(" / ")"
//			   pct-encoded          = "%" HEXDIG HEXDIG
//			   param-unreserved     = "[" / "]" / "/" / ":" / "&" / "+" / "$"
//   notes:
//       Same as RFC3261: paramchar, param-unreserved, mark, unreserved, pvalue
//	     Different: pname is more restrictive!

	
	private static final BitSet RFC3966_PNAME;
	static {
		RFC3966_PNAME = new BitSet();
		RFC3966_PNAME.or(RFC3261_ALPHA);
		RFC3966_PNAME.or(RFC3261_DIGIT);
		RFC3966_PNAME.set('-');
	}

	private static final BitSet RFC3966_PVALUE = RFC3261_PARAMCHAR;
	
	/** Default RFC-2396 safe character set. */
	static final BitSet DEFAULT_RFC2396;
	/** Initialize the BitSet */
	static {
		DEFAULT_RFC2396 = new BitSet(256);
		DEFAULT_RFC2396.or(RFC3261_ALPHA);
		DEFAULT_RFC2396.or(RFC3261_DIGIT);
		DEFAULT_RFC2396.set('-');
		DEFAULT_RFC2396.set('_');
		DEFAULT_RFC2396.set('.');
		DEFAULT_RFC2396.set('*');
		DEFAULT_RFC2396.set('"');
	}
	
	
	/** Encoding rules corresponding to RFC definitions. */
	public static enum EncodingRule {
		/** Default RFC-2396 encoding rule. */
		DEFAULT_RFC2396(RFC2396UrlDecoder.DEFAULT_RFC2396),
		
		/** Encoding rule used for <code>hname</code> and <code>hvalue</code>, as defined by RFC3261.*/
		RFC3261_HNAME_HVALUE(RFC2396UrlDecoder.RFC3261_HNAME_HVALUE),
		
		/** Encoding rule used for <code>pname</code> and <code>pvalue</code>, as defined by RFC3261.*/
		RFC3261_PNAME_PVALUE(RFC2396UrlDecoder.RFC3261_PNAME_PVALUE),
		
		/** Encoding rule used for tel URI <code>pname</code>, as defined by RFC3966.*/
		RFC3966_PNAME(RFC2396UrlDecoder.RFC3966_PNAME),
		
		/** Encoding rule used for tel URI <code>pvalue</code>, as defined by RFC3966.*/
		RFC3966_PVALUE(RFC2396UrlDecoder.RFC3966_PVALUE),
		;

		private final BitSet safeValues;

		EncodingRule(BitSet safeValues) {
			this.safeValues = safeValues;
		}
	}
	
	
	/**
	 * Translates a string into <code>x-www-form-urlencoded</code> format.
	 * Equivalent to calling {@link #encode(String, EncodingRule)} with {@link EncodingRule#DEFAULT_RFC2396}.
	 *
	 * @param   s   <code>String</code> to be translated.
	 * @return  the translated <code>String</code>.
	 * @deprecated Use {@link #encode(String, EncodingRule)} instead with an explicit rule specified.
	 */
	@Deprecated
	public static String encode(String s) {
		return encode(s, EncodingRule.DEFAULT_RFC2396);
	}
	
	/**
	 * Translates a string into percent-encoded format, based on the safe character set specified by the
	 * provided encoding rule (all other characters are considered unsafe and are percent-encoded).
	 * @param s The string to encode
	 * @param rule The {@link EncodingRule} to use.
	 * @return the percent-encoded string.
	 */
   	public static String encode(String s, EncodingRule rule) {
		final StringBuffer out = new StringBuffer(s.length());
		final ByteArrayOutputStream buf = new ByteArrayOutputStream(32);
		final OutputStreamWriter writer = new OutputStreamWriter(buf);
		for (int i = 0; i < s.length(); i++) {
			int c = s.charAt(i);
			if (rule.safeValues.get(c)) {
				out.append((char) c);
			} else {
				try {
					writer.write(c);
					writer.flush();
				} catch (IOException e) {
					buf.reset();
					continue;
				}
				byte[] ba = buf.toByteArray();
				for (int j = 0; j < ba.length; j++) {
					out.append('%');
					char ch = Character.forDigit((ba[j] >> 4) & 0xF, 16);
					// converting to use uppercase letter as part of
					// the hex value if ch is a letter.
					if (Character.isLetter(ch)) {
						ch -= CHARACTER_CASE_DIFF;
					}
					out.append(ch);
					ch = Character.forDigit(ba[j] & 0xF, 16);
					if (Character.isLetter(ch)) {
						ch -= CHARACTER_CASE_DIFF;
					}
					out.append(ch);
				}
				buf.reset();
			}
		}

		String ret = out.toString();
		if (logger.isTraceEnabled()) {
			logger.trace("Encoding rule " + rule + " turned ˛" + s + "¸ into ˛" + ret + "¸");
		}
		return ret;
	}

	
    private static final char UTF8_ESCAPE_CHAR = '%';
    
    /**
     * Decode a path.
     *
     * <p>Interprets %XX (where XX is hexadecimal number) as UTF-8 encoded bytes.
     * <p>The validity of the input path is not checked (i.e. characters that
     * were not encoded will not be reported as errors).
     * <p>This method differs from URLDecoder.decode in that it always uses UTF-8
     * (while URLDecoder uses the platform default encoding, often ISO-8859-1),
     * and doesn't translate + characters to spaces.
     *
     * @param uri the path to decode
     * @return the decoded path
     */
    public static String decode(String uri) {
    	if(logger.isDebugEnabled()) {
    		logger.debug("uri to decode " + uri);
    	}
    	if(uri == null) {
    		// fix by Hauke D. Issue 410
//    		throw new NullPointerException("uri cannot be null !");
    		return null;
    	}
        
        //optimization for uri with no escaped chars
        //fixes https://github.com/RestComm/sip-servlets/issues/124
        if (uri.indexOf(UTF8_ESCAPE_CHAR) < 0) {
            return uri;
        }
        
        StringBuffer translatedUri = new StringBuffer(uri.length());
        byte[] encodedchars = new byte[uri.length() / 3];
        int i = 0;
        int length = uri.length();
        int encodedcharsLength = 0;
        while (i < length) {
            if (uri.charAt(i) == UTF8_ESCAPE_CHAR) {
                //we must process all consecutive %-encoded characters in one go, because they represent
                //an UTF-8 encoded string, and in UTF-8 one character can be encoded as multiple bytes
                while (i < length && uri.charAt(i) == UTF8_ESCAPE_CHAR) {
                    if (i + 2 < length) {
                        try {
                            byte x = (byte)Integer.parseInt(uri.substring(i + 1, i + 3), 16);
                            encodedchars[encodedcharsLength] = x;
                        } catch (NumberFormatException e) {
                        	// do not throw exception, a % could be part of a IPv6 address and still be valid
//                            throw new IllegalArgumentException("Illegal hex characters in pattern %" + uri.substring(i + 1, i + 3));
                        }
                        encodedcharsLength++;
                        i += 3;
                    } else {
                    	// do not throw exception, a % could be part of a IPv6 address and still be valid
//                        throw new IllegalArgumentException("% character should be followed by 2 hexadecimal characters.");
                    }
                }
                try {
                    String translatedPart = new String(encodedchars, 0, encodedcharsLength, UTF_8);
                    translatedUri.append(translatedPart);
                } catch (UnsupportedEncodingException e) {
                    //the situation that UTF-8 is not supported is quite theoretical, so throw a runtime exception
                    throw new IllegalArgumentException("Problem in decodePath: UTF-8 encoding not supported.");
                }
                encodedcharsLength = 0;
            } else {
                //a normal character
                translatedUri.append(uri.charAt(i));
                i++;
            }
        }
        if(logger.isDebugEnabled()) {
    		logger.debug("decoded uri " + translatedUri);
    	}
        return translatedUri.toString();
    }
}