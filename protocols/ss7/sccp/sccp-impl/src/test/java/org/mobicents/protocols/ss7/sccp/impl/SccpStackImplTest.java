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

package org.mobicents.protocols.ss7.sccp.impl;

import java.io.IOException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.mobicents.protocols.StartFailedException;
import org.mobicents.protocols.ss7.indicator.NatureOfAddress;
import org.mobicents.protocols.ss7.sccp.SccpListener;
import org.mobicents.protocols.ss7.sccp.SccpProvider;
import org.mobicents.protocols.ss7.sccp.message.MessageFactory;
import org.mobicents.protocols.ss7.sccp.message.MessageType;
import org.mobicents.protocols.ss7.sccp.message.SccpMessage;
import org.mobicents.protocols.ss7.sccp.message.UnitData;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle;
import org.mobicents.protocols.ss7.sccp.parameter.ParameterFactory;
import org.mobicents.protocols.ss7.sccp.parameter.ProtocolClass;
import org.mobicents.protocols.ss7.sccp.parameter.SccpAddress;

/**
 *
 * @author kulikov
 */
public class SccpStackImplTest {

    private SccpStackImpl stack = new SccpStackImpl();
    private SccpAddress a1, a2;
    
    public SccpStackImplTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() throws IllegalStateException, StartFailedException {
        stack.start();
        
        GlobalTitle gt1 = GlobalTitle.getInstance(NatureOfAddress.NATIONAL, "1234");
        GlobalTitle gt2 = GlobalTitle.getInstance(NatureOfAddress.NATIONAL, "5678");
        
        a1 = new SccpAddress(gt1, 0);
        a2 = new SccpAddress(gt2, 0);
    }

    @After
    public void tearDown() {
        stack.stop();
    }

    /**
     * Test of configure method, of class SccpStackImpl.
     */
    @Test
    public void testLocalRouting() throws Exception {
        User u1 = new User(stack.getSccpProvider(), a1, a2);
        User u2 = new User(stack.getSccpProvider(), a2, a1);
        
        u1.send();
        u2.send();
        
        Thread.currentThread().sleep(1000);
        
        assertTrue("Message not received", u1.check());
        assertTrue("Message not received", u2.check());
    }

    private class User implements SccpListener {
        private SccpProvider provider;
        private SccpAddress address;
        private SccpAddress dest;
        
        private SccpMessage msg;
        
        public User(SccpProvider provider, SccpAddress address, SccpAddress dest) {
            this.provider = provider;
            this.address = address;
            this.dest = dest;
            provider.registerSccpListener(address, this);
        }
        
        public boolean check() {
            if (msg == null) {
                return false;
            }
            
            if (msg.getType() != MessageType.UDT) {
                return false;
            }
            
            UnitData udt = (UnitData) msg;
            if (!address.equals(udt.getCalledPartyAddress())) {
                return false;
            }
            
            if (!dest.equals(udt.getCallingPartyAddress())) {
                return false;
            }
            
            return true;
        }
        
        private void send() throws IOException {
            MessageFactory messageFactory = provider.getMessageFactory();
            ParameterFactory paramFactory = provider.getParameterFactory();
            
            ProtocolClass pClass = paramFactory.createProtocolClass(0, 0);
            UnitData udt = messageFactory.createUnitData(pClass, address, dest);
            udt.setData(new byte[10]);
            provider.send(udt);
        }
        
        public void onMessage(SccpMessage message) {
            this.msg = message;
        }
        
    }
}