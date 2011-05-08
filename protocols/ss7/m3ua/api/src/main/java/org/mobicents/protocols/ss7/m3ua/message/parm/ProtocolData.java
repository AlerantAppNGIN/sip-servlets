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

package org.mobicents.protocols.ss7.m3ua.message.parm;

import org.mobicents.protocols.ss7.m3ua.message.Parameter;

/**
 * Protocl data parameter.
 * 
 * @author kulikov
 */
public interface ProtocolData extends Parameter {
    /** 
     * Gets origination point code.
     * 
     * @return point code value in decimal format.
     */
    public int getOpc();
    
    /**
     * Gets destination point code
     * 
     * @return point code value in decimal format
     */
    public int getDpc();
    
    /**
     * Gets the service indicator.
     * 
     * @return service indicator value.
     */
    public int getSI();
    
    /**
     * Gets the network indicator.
     * 
     * @return the network indicator value.
     */
    public int getNI();
    
    /**
     * Gets the message priority.
     * 
     * @return message priority value.
     */
    public int getMP();
    
    /**
     * Gets the signaling link selection.
     * 
     * @return the signaling link selection value
     */
    public int getSLS();

    /**
     * Gets the payload of message.
     * 
     * @return binary message.
     */
    public byte[] getData();

    /**
     * Gets the message encoded as SS7 message signaling unit.
     * 
     * @return binary message signaling unit
     */
    public byte[] getMsu();
}
