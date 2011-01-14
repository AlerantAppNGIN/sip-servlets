/*
 * JBoss, Home of Professional Open Source
 * Copyright XXXX, Red Hat Middleware LLC, and individual contributors as indicated
 * by the @authors tag. All rights reserved.
 * See the copyright.txt in the distribution for a full listing
 * of individual contributors.
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License, v. 2.0.
 * This program is distributed in the hope that it will be useful, but WITHOUT A
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License,
 * v. 2.0 along with this distribution; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */
package org.mobicents.protocols.ss7.sccp.parameter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.mobicents.protocols.ss7.indicator.EncodingScheme;
import org.mobicents.protocols.ss7.indicator.GlobalTitleIndicator;
import org.mobicents.protocols.ss7.indicator.NumberingPlan;

/**
 *
 * @author kulikov
 */
public class GT0011  extends GlobalTitle {
    private final static GlobalTitleIndicator gti = GlobalTitleIndicator.GLOBAL_TITLE_INCLUDES_TRANSLATION_TYPE_NUMBERING_PLAN_AND_ENCODING_SCHEME;
    private int tt;    
    private NumberingPlan np;
    private EncodingScheme es;
    
    private String digits;
    
    public GT0011() {
        digits = "";
    }
    
    public GT0011(int tt, NumberingPlan np, String digits) {
        this.tt = tt;
        this.np = np;
        this.digits = digits;
        this.es = digits.length() % 2 == 0 ? EncodingScheme.BCD_EVEN : EncodingScheme.BCD_ODD;
    }

    public void decode(InputStream in) throws IOException {
        int b = in.read() & 0xff;        
        tt = b;
        
        b = in.read() & 0xff;
        
        es = EncodingScheme.valueOf(b & 0x0f);
        np = NumberingPlan.valueOf((b & 0xf0)>>4);
        
        digits = es.decodeDigits(in);
    }

    public void encode(OutputStream out) throws IOException {
        out.write(tt);
        out.write((np.getValue() << 4) | es.getValue());
        es.encodeDigits(digits, out);
    }

    public int getTranslationType() {
        return tt;
    }

    public NumberingPlan getNp() {
        return np;
    }
    
    public String getDigits() {
        return digits;
    }

    public GlobalTitleIndicator getIndicator() {
        return gti;
    }
    
    @Override
    public boolean equals(Object other) {
        if (!(other instanceof GlobalTitle)) {
            return false;
        }
        
        GlobalTitle gt = (GlobalTitle) other;
        if (gt.getIndicator() != gti) {
            return false;
        }
        
        GT0011 gt1 = (GT0011)gt;
        return gt1.tt == tt && gt1.np == np && gt1.digits.equals(digits);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 41 * hash + this.tt;
        hash = 41 * hash + (this.np != null ? this.np.hashCode() : 0);
        hash = 41 * hash + (this.digits != null ? this.digits.hashCode() : 0);
        return hash;
    }
    
}
