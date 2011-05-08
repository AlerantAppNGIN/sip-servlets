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

package org.mobicents.protocols.ss7.sccp.impl;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.mobicents.protocols.ss7.sccp.SccpListener;
import org.mobicents.protocols.ss7.sccp.SccpProvider;
import org.mobicents.protocols.ss7.sccp.impl.message.MessageFactoryImpl;
import org.mobicents.protocols.ss7.sccp.impl.parameter.ParameterFactoryImpl;
import org.mobicents.protocols.ss7.sccp.message.MessageFactory;
import org.mobicents.protocols.ss7.sccp.message.SccpMessage;
import org.mobicents.protocols.ss7.sccp.parameter.ParameterFactory;
import org.mobicents.protocols.ss7.sccp.parameter.SccpAddress;

/**
 * 
 * @author Oleg Kulikov
 * @author baranowb
 */
public class SccpProviderImpl implements SccpProvider, Serializable {
	//TODO: Oleg, this is not serializable resource!
	private static final Logger logger = Logger.getLogger(SccpProviderImpl.class);
    private transient SccpStackImpl stack;
    private HashMap<SccpAddress, SccpListener> listeners = new HashMap();
    
    private MessageFactoryImpl messageFactory;
    private ParameterFactoryImpl parameterFactory;
    
    SccpProviderImpl(SccpStackImpl stack) {
        this.stack = stack;
        this.messageFactory = stack.messageFactory;
        this.parameterFactory = new ParameterFactoryImpl();
    }

    public MessageFactory getMessageFactory() {
        return messageFactory;
    }

    public ParameterFactory getParameterFactory() {
        return parameterFactory;
    }

    public void registerSccpListener(SccpAddress localAddress, SccpListener listener) {
        listeners.put(localAddress, listener);
    }

    public void deregisterSccpListener(SccpAddress localAddress) {
        listeners.remove(localAddress);
    }

    /**
     * Sends notification to listeners.
     * 
     * @param address the address associated with listener.
     * @param message the message to deliver to listener
     */
    protected void notify(SccpAddress address, SccpMessage message) {
        SccpListener listener = listeners.get(address);
        if(listener == null)
        {
            logger.info("Registere listeners for: " + listeners.keySet());
        	if(logger.isEnabledFor(Level.WARN))
        	{
        		logger.warn("No listener could be found for address: "+address);
        	}
        	
        }else
        {
        	listener.onMessage(message);
        }
    }

    public void send(SccpMessage message) throws IOException {
        stack.send(message);
    }
}
