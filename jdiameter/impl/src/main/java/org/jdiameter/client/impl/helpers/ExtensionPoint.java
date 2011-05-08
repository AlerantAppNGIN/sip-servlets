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

package org.jdiameter.client.impl.helpers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * This class provide pluggable features
 */
public class ExtensionPoint extends Ordinal {

  private static final long serialVersionUID = 1L;

    protected static int index;

    private static ArrayList<Parameters> value = new ArrayList<Parameters>();

    /**
     * MetaData implementation class name
     */
    public static final ExtensionPoint InternalMetaData = new ExtensionPoint("InternalMetaData", "org.jdiameter.client.impl.MetaDataImpl");

    /**
     * Message parser implementation class name
     */
    public static final ExtensionPoint InternalMessageParser = new ExtensionPoint("InternalMessageParser", "org.jdiameter.client.impl.parser.MessageParser");

    /**
     * Element message implementation class name
     */
    public static final ExtensionPoint InternalElementParser = new ExtensionPoint("InternalElementParser", "org.jdiameter.client.impl.parser.ElementParser");

    /**
     * Router enginr implementation class name
     */
    public static final ExtensionPoint InternalRouterEngine = new ExtensionPoint("InternalRouterEngine", "org.jdiameter.client.impl.router.RouterImpl");

    /**
     * Peer controller implementation class name
     */
    public static final ExtensionPoint InternalPeerController = new ExtensionPoint("InternalPeerController", "org.jdiameter.client.impl.controller.PeerTableImpl");

    /**
     * Session factiry implementation class name
     */
    public static final ExtensionPoint InternalSessionFactory = new ExtensionPoint("InternalSessionFactory", "org.jdiameter.client.impl.SessionFactoryImpl");

    /**
     * Transport factory implementation class name
     */
    public static final ExtensionPoint InternalTransportFactory = new ExtensionPoint("InternalTransportFactory", "org.jdiameter.client.impl.transport.TransportLayerFactory");

    /**
     * Peer fsm factory implementation class name
     */
    public static final ExtensionPoint InternalPeerFsmFactory = new ExtensionPoint("InternalPeerFsmFactory", "org.jdiameter.client.impl.fsm.FsmFactoryImpl");

    /**
     * Statistic factory implementation class name
     */
    public static final ExtensionPoint InternalStatisticFactory = new ExtensionPoint("InternalStatisticFactory", "org.jdiameter.common.impl.statistic.StatisticFactory");

    /**
     * Statistic factory implementation class name
     */
    public static final ExtensionPoint InternalStatisticProcessor = new ExtensionPoint("InternalStatisticProcessor", "org.jdiameter.common.impl.statistic.StatisticProcessor");

    /**
     * Concurrent factory implementation class name
     */
    public static final ExtensionPoint InternalConcurrentFactory = new ExtensionPoint("InternalConcurrentFactory", "org.jdiameter.common.impl.concurrent.ConcurrentFactory");

    /**
     * List of internal extension point
     */
    public static final ExtensionPoint Internal = new ExtensionPoint(
            "Internal", 0,
            InternalMetaData,
            InternalMessageParser,
            InternalElementParser,
            InternalRouterEngine,
            InternalPeerController,
            InternalSessionFactory,
            InternalTransportFactory,
            InternalPeerFsmFactory,
            InternalStatisticFactory,
            InternalConcurrentFactory,
            InternalStatisticProcessor
    );

    /**
     * Stack layer
     */
    public static final ExtensionPoint StackLayer = new ExtensionPoint("StackLayer", 0);

    /**
     * Controller layer
     */
    public static final ExtensionPoint ControllerLayer = new ExtensionPoint("ControllerLayer", 1);

    /**
     * Transport layer
     */
    public static final ExtensionPoint TransportLayer = new ExtensionPoint("TransportLayer", 2);

    /**
     * Return Iterator of all entries
     * 
     * @return  Iterator of all entries
     */
    public static Iterable<Parameters> values() {
        return value;
    }

    private ExtensionPoint[] elements = new ExtensionPoint[0];
    private String defaultValue = "";
    private int id = -1;

    /**
     * Type's count of extension point
     */
    public static final int COUNT = 3;

    /**
     * Create instance of class
     */
    public ExtensionPoint() {
        this.ordinal = index++;
    }

    protected ExtensionPoint(String name, String defaultValue) {
        this();
        this.name = name;
        this.defaultValue = defaultValue;
    }

    protected ExtensionPoint(String name, ExtensionPoint... elements) {
        this();
        this.name = name;
        this.elements = elements;
    }

    protected ExtensionPoint(String name, int id, ExtensionPoint... elements) {
        this();
        this.name = name;
        this.id = id;
        this.elements = elements;
    }

    /**
     * Append extension point entries
     * 
     * @param elements array of append extension point entries
     */
    public void appendElements(ExtensionPoint... elements) {
        List<ExtensionPoint> rc = new ArrayList<ExtensionPoint>();
        rc.addAll(Arrays.asList(this.elements));
        rc.addAll(Arrays.asList(elements));
        this.elements = rc.toArray(new ExtensionPoint[0]);
    }

    /**
     * Return parameters of extension point
     * 
     * @return array parameters of extension point
     */
    public ExtensionPoint[] getArrayOfParameters() {
        return elements;
    }

    /**
     * Return default value of extension point
     * 
     * @return default value of extension point
     */
    public String defValue() {
        return defaultValue;
    }

    /**
     * Return id of extension point
     * 
     * @return id of extension point
     */
    public int id() {
        return id;
    }
}
