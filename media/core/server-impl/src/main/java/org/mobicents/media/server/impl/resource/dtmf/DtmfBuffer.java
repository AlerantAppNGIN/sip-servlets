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

package org.mobicents.media.server.impl.resource.dtmf;

import java.io.Serializable;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.mobicents.media.server.impl.AbstractSink;
import org.mobicents.media.server.spi.resource.DtmfDetector;

/**
 * Implements digit buffer.
 * 
 * @author Oleg Kulikov
 * @author amit bhayani
 */
public abstract class DtmfBuffer extends AbstractSink implements DtmfDetector, Serializable {

    public final static int TIMEOUT = 5000;
    private static final String DETECTOR_MASK = "[0-9, A,B,C,D,*,#]";    // Silence is time difference forced between two digits. Default is user 2
    // digits per sec. Reduce this to suit your requirements
    public int interdigitInterval = DEFAULT_INTERDIGIT_INTERVAL;
    private StringBuffer buffer = new StringBuffer();
    
    private Matcher matcher;
    private String mask;
    private Pattern maskPattern;
    
    private long lastActivity = System.currentTimeMillis();
    private String lastSymbol;
    private transient Logger logger = Logger.getLogger(DtmfBuffer.class);

    public DtmfBuffer(String name) {
        super(name);
        buffer = new StringBuffer();
        
        maskPattern = Pattern.compile(DETECTOR_MASK);
        setMask(DETECTOR_MASK);
    }

    public String getMask() {
        return mask;
    }

    public void setMask(String mask) {
        this.mask = mask;
    }

    public void setInterdigitInterval(int silence) {
        this.interdigitInterval = silence;
    }

    public int getInterdigitInterval() {
        return this.interdigitInterval;
    }

    public void push(String symbol) {
        long now = System.currentTimeMillis();

        if (now - lastActivity > TIMEOUT) {
            buffer = new StringBuffer();
        }
        
        if (!symbol.equals(lastSymbol) || (now - lastActivity > interdigitInterval)) {
            buffer.append(symbol);
            lastActivity = now;
            lastSymbol = symbol;
            String digits = buffer.toString();
            
            matcher = maskPattern.matcher(digits);
            if (matcher.matches()) {
                // send event;
                if (logger.isDebugEnabled()) {
                    logger.debug("Send DTMF event: " + digits);
                }

                int eventId = 0;
                if (digits.equals("0")) {
                    eventId = DtmfEvent.DTMF_0;
                } else if (digits.equals("1")) {
                    eventId = DtmfEvent.DTMF_1;
                } else if (digits.equals("2")) {
                    eventId = DtmfEvent.DTMF_2;
                } else if (digits.equals("3")) {
                    eventId = DtmfEvent.DTMF_3;
                } else if (digits.equals("4")) {
                    eventId = DtmfEvent.DTMF_4;
                } else if (digits.equals("5")) {
                    eventId = DtmfEvent.DTMF_5;
                } else if (digits.equals("6")) {
                    eventId = DtmfEvent.DTMF_6;
                } else if (digits.equals("7")) {
                    eventId = DtmfEvent.DTMF_7;
                } else if (digits.equals("8")) {
                    eventId = DtmfEvent.DTMF_8;
                } else if (digits.equals("9")) {
                    eventId = DtmfEvent.DTMF_9;
                } else if (digits.equals("A")) {
                    eventId = DtmfEvent.DTMF_A;
                } else if (digits.equals("B")) {
                    eventId = DtmfEvent.DTMF_B;
                } else if (digits.equals("C")) {
                    eventId = DtmfEvent.DTMF_C;
                } else if (digits.equals("D")) {
                    eventId = DtmfEvent.DTMF_D;
                } else if (symbol.equals("*")) {
                    eventId = DtmfEvent.DTMF_STAR;
                } else if (symbol.equals("#")) {
                    eventId = DtmfEvent.DTMF_HASH;
                } else {
                    logger.error("DTMF event " + symbol + " not identified");
                    return;
                }

                DtmfEvent dtmfEvent = new DtmfEvent(this, eventId, 0);
                super.sendEvent(dtmfEvent);

                buffer = new StringBuffer();
            }
        }

    }
}
