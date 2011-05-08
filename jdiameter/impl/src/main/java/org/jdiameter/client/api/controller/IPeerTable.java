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

package org.jdiameter.client.api.controller;

import org.jdiameter.api.*;
import org.jdiameter.client.api.IAssembler;
import org.jdiameter.client.api.IMessage;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ExecutorService;

/**
 *  This interface provide additional methods for PeerTable interface
 */
public interface IPeerTable extends PeerTable {

    /**
     * Start peer manager ( start network activity )
     * 
     * @throws IllegalDiameterStateException
     * @throws IOException
     */
    void start() throws IllegalDiameterStateException, IOException;

    /**
     * Run stopping procedure (unsynchronized)
     */
    void stopping();

    /**
     * Release resources
     */
    void stopped();

    /**
     *  Destroy all resources
     */
    void destroy();

    /**
     * Send message to diameter network ( routing procedure )
     * 
     * @param message  message instance
     * @throws IllegalDiameterStateException
     * @throws IOException
     * @throws RouteException
     * @throws AvpDataException
     */
    void sendMessage(IMessage message) throws IllegalDiameterStateException, IOException, RouteException, AvpDataException;

    /**
     * Register session lister
     * 
     * @param sessionId session id
     * @param listener listener listener
     */
    void addSessionReqListener(String sessionId, NetworkReqListener listener);

    /**
     * Return peer from peer table by peerURI
     * 
     * @param peerHost peer host
     * @return peer instance
     */
    IPeer getPeerByName(String peerHost);

    /**
     * Return peer from peer table by peerURI
     * 
     * @param peerUri peer uri
     * @return peer instance
     */
    IPeer getPeerByUri(String peerUri);

    /**
     * Return map of session event listeners
     * 
     * @return map of session event listeners
     */
    Map<String, NetworkReqListener> getSessionReqListeners();

    /**
     * Remove session event listener
     * 
     * @param sessionId id of session
     */
    void removeSessionListener(String sessionId);

    /**
     * Set instance assembler
     * 
     * @param assembler assembler instance
     */
    void setAssembler(IAssembler assembler);
}
