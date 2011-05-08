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

package org.jdiameter.server.impl.helpers;

public class Parameters extends org.jdiameter.client.impl.helpers.Parameters {

    /**
     *  Array of local host ip addresses property
     */
    public static final Parameters OwnIPAddresses = new Parameters("OwnIPAddresses", Object.class);
    /**
     *  On/Off duplication protection property
     */
    public static final Parameters DuplicateProtection = new Parameters("DuplicateProtection", Boolean.class, false);
    /**
     * Duplication clear task time period property
     */
    public static final Parameters DuplicateTimer = new Parameters("DuplicateTimer", Long.class, 4 * 60 * 1000L);
    /**
     * On/Off
     */
    public static final Parameters AcceptUndefinedPeer = new Parameters("PeerAcceptUndefinedPeer", Boolean.class, false);
    /**
     * Realm name property
     */
    public static final Parameters RealmName = new Parameters("RealmName", String.class, "");
    /**
     * Realm hosts property
     */
    public static final Parameters RealmHosts = new Parameters("RealmHosts", String.class, "localhost");
    /**
     * Realm action property
     */
    public static final Parameters RealmLocalAction = new Parameters("RealmLocalAction", String.class, "LOCAL");
    /**
     * Realm EntryIsDynamic
     */
    public static final Parameters RealmEntryIsDynamic = new Parameters("RealmEntryIsDynamic", Boolean.class, false);
    /**
     *  Realm EntryExpTime
     */
    public static final Parameters RealmEntryExpTime = new Parameters("RealmEntryExpTime", Long.class, 0);
    /**
     * Overload monitor property
     */
    public static final Parameters OverloadMonitor = new Parameters("OverloadMonitor", Object.class, "");
    /**
     *  Overload monitor entry property
     */
    public static final Parameters OverloadMonitorEntry = new Parameters("OverloadMonitorEntry", Object.class, "");
    /**
     * Overload monitor data property
     */
    public static final Parameters OverloadMonitorData  = new Parameters("OverloadMonitorData", Object.class, "");
    /**
     * Overload entry Index property
     */
    public static final Parameters OverloadEntryIndex   = new Parameters("OverloadEntryIndex", Integer.class, "");
    /**
     * Overload high threshold property
     */
    public static final Parameters OverloadEntryhighThreshold = new Parameters("OverloadEntryhighThreshold", Double.class, "");
    /**
     * Overload low threshold property
     */
    public static final Parameters OverloadEntrylowThreshold  = new Parameters("OverloadEntrylowThreshold", Double.class, "");
    /**
     * Peer reconnection property property
     */
    public static final Parameters PeerAttemptConnection = new Parameters("PeerAttemptConnection", Boolean.class, false);

    /**
     * Peer reconnection property property
     */
    public static final Parameters NeedClientAuth = new Parameters("NeedClientAuth", Boolean.class);

    protected Parameters(String name, Class type) {
        super(name, type);
    }

    protected Parameters(String name, Class type, Object defValue) {
        super(name, type, defValue);
    }
}
