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

package org.jdiameter.server.impl.fsm;

import org.jdiameter.api.Configuration;
import org.jdiameter.api.ConfigurationListener;
import org.jdiameter.api.MutableConfiguration;
import org.jdiameter.api.ResultCode;
import org.jdiameter.api.app.State;
import org.jdiameter.api.app.StateEvent;
import org.jdiameter.client.api.IMessage;

import org.jdiameter.client.api.fsm.IContext;
import static org.jdiameter.client.impl.fsm.FsmState.*;
import org.jdiameter.common.api.concurrent.IConcurrentFactory;
import org.jdiameter.common.api.statistic.IStatisticFactory;
import org.jdiameter.server.api.IStateMachine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PeerFSMImpl extends org.jdiameter.client.impl.fsm.PeerFSMImpl implements IStateMachine, ConfigurationListener {

  private static final Logger logger = LoggerFactory.getLogger(org.jdiameter.server.impl.fsm.PeerFSMImpl.class);

  public PeerFSMImpl(IContext context, IConcurrentFactory concurrentFactory, Configuration config, IStatisticFactory statisticFactory) {
    super(context, concurrentFactory, config, statisticFactory);
  }

  protected void loadTimeOuts(Configuration config) {
    super.loadTimeOuts(config);
    if (config instanceof MutableConfiguration) {
      ((MutableConfiguration) config).addChangeListener(this, 0);
    }
  }

  public boolean elementChanged(int i, Object data) {
    Configuration newConfig = (Configuration) data;
    super.loadTimeOuts(newConfig);
    return true;
  }

  protected State[] getStates() {
    if (states == null) {
      states = new State[] {
          new MyState() // OKEY
          {
            public void entryAction() { // todo send buffered messages
              setInActiveTimer();
              watchdogSent = false;
            }

            public boolean processEvent(StateEvent event) {
              switch (type(event)) {
              case DISCONNECT_EVENT:
                doEndConnection();
                break;
              case TIMEOUT_EVENT:
                try {
                  context.sendDwrMessage();
                  setTimer(DWA_TIMEOUT);
                  if (watchdogSent) {
                    switchToNextState(SUSPECT);
                  }
                  else {
                    watchdogSent = true;
                  }
                }
                catch (Throwable e) {
                  logger.debug("Can not send DWR", e);
                  doDisconnect();
                  doEndConnection();
                }
                break;
              case STOP_EVENT:
                try { // TODO: send user code;
                  context.sendDprMessage(ResultCode.SUCCESS);
                  setTimer(DPA_TIMEOUT);
                  switchToNextState(STOPPING);
                }
                catch (Throwable e) {
                  logger.debug("Can not send DPR", e);
                  doDisconnect();
                  switchToNextState(DOWN);
                }
                break;
              case RECEIVE_MSG_EVENT:
                setInActiveTimer();
                context.receiveMessage(message(event));
                break;
              case CEA_EVENT:
                setInActiveTimer();
                if (context.processCeaMessage(key(event), message(event))) {
                  doDisconnect(); // !
                  doEndConnection();
                }
                break;
              case CER_EVENT:
                setInActiveTimer();
                // Skip
                break;
              case DPR_EVENT:
                try {
                  int code = context.processDprMessage((IMessage) event.getData());
                  context.sendDpaMessage(message(event), code, null);
                }
                catch (Throwable e) {
                  logger.debug("Can not send DPA", e);
                }
                doDisconnect();
                switchToNextState(DOWN);
                break;
              case DWR_EVENT:
                setInActiveTimer();
                try {
                  context.sendDwaMessage(message(event), ResultCode.SUCCESS, null);
                }
                catch (Throwable e) {
                  logger.debug("Can not send DWA", e);
                  doDisconnect();
                  switchToNextState(DOWN);
                }
                break;
              case DWA_EVENT:
                setInActiveTimer();
                watchdogSent = false;
                break;
              case SEND_MSG_EVENT:
                try {
                  context.sendMessage(message(event));
                }
                catch (Throwable e) {
                  logger.debug("Can not send message", e);
                  doDisconnect();
                  doEndConnection();
                }
                break;
              default:
                logger.debug("Unknown event type {} in state {}", type(event), state);
              return false;
              }
              return true;
            }
          },
          new MyState() // SUSPECT
          {
            public boolean processEvent(StateEvent event) {
              switch (type(event)) {
              case DISCONNECT_EVENT:
                doEndConnection();
                break;
              case TIMEOUT_EVENT:
                doDisconnect();
                doEndConnection();
                break;
              case STOP_EVENT:
                try {
                  context.sendDprMessage(ResultCode.SUCCESS);
                  setInActiveTimer();
                  switchToNextState(STOPPING);
                }
                catch (Throwable e) {
                  logger.debug("Can not send DPR", e);
                  doDisconnect();
                  switchToNextState(DOWN);
                }
                break;
              case CER_EVENT:
              case CEA_EVENT:
              case DWA_EVENT:
                clearTimer();
                switchToNextState(OKAY);
                break;
              case DPR_EVENT:
                try {
                  int code = context.processDprMessage((IMessage) event.getData());
                  context.sendDpaMessage(message(event), code, null);
                }
                catch (Throwable e) {
                  logger.debug("Can not send DPA", e);
                }
                doDisconnect();
                switchToNextState(DOWN);
                break;
              case DWR_EVENT:
                try {
                  int code = context.processDwrMessage((IMessage) event.getData());
                  context.sendDwaMessage(message(event),code, null);
                  switchToNextState(OKAY);
                }
                catch (Throwable e) {
                  logger.debug("Can not send DWA", e);
                  doDisconnect();
                  switchToNextState(DOWN);
                }
                break;
              case RECEIVE_MSG_EVENT:
                clearTimer();
                context.receiveMessage(message(event));
                switchToNextState(OKAY);
                break;
              case SEND_MSG_EVENT: // todo buffering
                throw new IllegalStateException("Connection is down");
              default:
                logger.debug("Unknown event type {} in state {}", type(event), state);
              return false;
              }
              return true;
            }
          },
          new MyState() // DOWN
          {
            public void entryAction() {
              setTimer(0);
              if(!context.isRestoreConnection()) {
                executor = null;
              }
            }

            public boolean processEvent(StateEvent event) {
              switch (type(event)) {
              case START_EVENT:
                try {
                  if (!context.isConnected()) {
                    context.connect();                              
                  }
                  context.sendCerMessage();
                  setTimer(CEA_TIMEOUT);
                  switchToNextState(INITIAL);
                }
                catch (Throwable e) {
                  logger.debug("Connect error", e);
                  doEndConnection();
                }
                break;
              case CER_EVENT:
                int resultCode = context.processCerMessage(key(event), message(event));
                if (resultCode == ResultCode.SUCCESS) {
                  try {
                    context.sendCeaMessage(resultCode, message(event), null);
                    switchToNextState(OKAY);
                  }
                  catch (Exception e) {
                    logger.debug("Failed to send CEA.", e);
                    doDisconnect();  // !
                    doEndConnection();
                  }
                }
                else {
                  try {
                    context.sendCeaMessage(resultCode, message(event),  null);
                  }
                  catch (Exception e) {
                    logger.debug("Failed to send CEA.", e);
                  }
                  doDisconnect(); // !
                  doEndConnection();
                }
                break;
              case SEND_MSG_EVENT:
                // todo buffering
                throw new IllegalStateException("Connection is down");
              case STOP_EVENT:
              case TIMEOUT_EVENT:    
              case DISCONNECT_EVENT:
                break;
              default:
                logger.debug("Unknown event type {} in state {}", type(event), state);                          
              return false;
              }
              return true;
            }
          },
          new MyState() // REOPEN
          {
            public boolean processEvent(StateEvent event) {
              switch (type(event)) {
              case CONNECT_EVENT:
                try {
                  context.sendCerMessage();
                  setTimer(CEA_TIMEOUT);
                  switchToNextState(INITIAL);
                }
                catch (Throwable e) {
                  logger.debug("Can not send CER", e);
                  setTimer(REC_TIMEOUT);
                }
                break;
              case TIMEOUT_EVENT:
                try {                              
                  context.connect();
                }
                catch (Exception e) {
                  logger.debug("Can not connect to remote peer", e);
                  setTimer(REC_TIMEOUT);
                }
                break;
              case STOP_EVENT:
                setTimer(0);
                doDisconnect();
                switchToNextState(DOWN);
                break;
              case DISCONNECT_EVENT:
                break;
              case SEND_MSG_EVENT:
                // todo buffering
                throw new IllegalStateException("Connection is down");
              default:
                logger.debug("Unknown event type {} in state {}", type(event), state);                          
              return false;
              }
              return true;
            }
          },
          new MyState() // INITIAL
          {
            public void entryAction() {
              setTimer(CEA_TIMEOUT);
            }

            public boolean processEvent(StateEvent event) {
              switch (type(event)) {
              case DISCONNECT_EVENT:
                setTimer(0);
                doEndConnection();
                break;
              case TIMEOUT_EVENT:
                doDisconnect();
                doEndConnection();
                break;
              case STOP_EVENT:
                setTimer(0);
                doDisconnect();
                switchToNextState(DOWN);
                break;
              case CEA_EVENT:
                setTimer(0);
                if (context.processCeaMessage(key(event), message(event))) {
                  switchToNextState(OKAY);
                }
                else {
                  doDisconnect(); // !
                  doEndConnection();
                }
                break;
              case CER_EVENT:
                int resultCode = context.processCerMessage(key(event), message(event));
                if (resultCode == ResultCode.SUCCESS) {
                  try {
                    context.sendCeaMessage(resultCode, message(event), null);
                    switchToNextState(OKAY); // if other connection is win
                  }
                  catch (Exception e) {
                    logger.debug("Can not send CEA", e);
                    doDisconnect();
                    doEndConnection();
                  }
                }
                else if (resultCode == -1 || resultCode == ResultCode.NO_COMMON_APPLICATION) {
                  doDisconnect();
                  doEndConnection();
                }
                break;
              case SEND_MSG_EVENT:
                // todo buffering
                throw new IllegalStateException("Connection is down");
              default:
                logger.debug("Unknown event type {} in state {}", type(event), state);                          
              return false;
              }
              return true;
            }
          },
          new MyState() // STOPPING
          {
            public boolean processEvent(StateEvent event) {
              switch (type(event)) {
              case TIMEOUT_EVENT:
              case DPA_EVENT:
                switchToNextState(DOWN);
                break;
              case RECEIVE_MSG_EVENT:
                context.receiveMessage(message(event));
                break;
              case SEND_MSG_EVENT:
                throw new IllegalStateException("Stack now is stopping");
              case STOP_EVENT:
              case DISCONNECT_EVENT:
                break;
              default:
                logger.debug("Unknown event type {} in state {}", type(event), state);                          
              return false;
              }
              return true;
            }
          }
      };
    }

    return states;
  }
}
