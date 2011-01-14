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
package org.mobicents.protocols.ss7.m3ua;

/**
 * A token representing the registration of a M3UAChannel with a multiplexer.
 * 
 * A selection key is created each time a channel is registered with a selector. 
 * A key remains valid until it is cancelled by invoking its cancel method, by closing 
 * its channel, or by closing its selector. Cancelling a key does not immediately remove 
 * it from its selector.
 * 
 * A selection key is created each time a channel is registered with a selector. 
 * A key remains valid until it is cancelled by invoking its cancel method, by closing its channel, 
 * or by closing its selector. Cancelling a key does not immediately remove it from its selector
 * 
 * That a selection key's ready set indicates that its channel is ready for some operation 
 * category is a hint, but not a guarantee, that an operation in such a category may be 
 * performed by a thread without causing the thread to block. A ready set is most likely to be 
 * accurate immediately after the completion of a selection operation. It is likely to be made 
 * inaccurate by external events and by I/O operations that are invoked upon the corresponding 
 * channel.
 * 
 * @author kulikov
 */
public interface M3UASelectionKey {
    /**
     * Returns the channel for which this key was created. 
     * This method will continue to return the channel even after the key is cancelled.
     * 
     * @return This key's channel.
     */
    public M3UASelectableChannel channel();
    
    /**
     * Tests whether this key's channel is ready to accept a new connection.
     * 
     * @return true if, and only if channel ready to accept new connection
     */
    public boolean isAcceptable();
    
    /**
     * Tests whether this key's channel is ready for reading.
     * 
     * @return true if, and only if channel ready for reading
     */
    public boolean isReadable();
    
    /**
     * Tests whether this key's channel is ready for writting.
     * 
     * @return true if, and only if channel ready for writting
     */
    public boolean isWritable();
    
    /**
     * Requests that the registration of this key's channel with its selector be cancelled. 
     */
    public void cancel();

}
