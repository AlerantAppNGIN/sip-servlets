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

package org.jdiameter.server.impl.app.ro;

import java.io.Serializable;
import java.util.Arrays;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.jdiameter.api.Answer;
import org.jdiameter.api.Avp;
import org.jdiameter.api.AvpDataException;
import org.jdiameter.api.EventListener;
import org.jdiameter.api.IllegalDiameterStateException;
import org.jdiameter.api.InternalException;
import org.jdiameter.api.NetworkReqListener;
import org.jdiameter.api.OverloadException;
import org.jdiameter.api.Request;
import org.jdiameter.api.RouteException;
import org.jdiameter.api.SessionFactory;
import org.jdiameter.api.app.AppAnswerEvent;
import org.jdiameter.api.app.AppEvent;
import org.jdiameter.api.app.AppRequestEvent;
import org.jdiameter.api.app.AppSession;
import org.jdiameter.api.app.StateChangeListener;
import org.jdiameter.api.app.StateEvent;
import org.jdiameter.api.auth.events.ReAuthRequest;
import org.jdiameter.api.ro.ServerRoSession;
import org.jdiameter.api.ro.ServerRoSessionListener;
import org.jdiameter.api.ro.events.RoCreditControlAnswer;
import org.jdiameter.api.ro.events.RoCreditControlRequest;
import org.jdiameter.client.api.IContainer;
import org.jdiameter.client.api.ISessionFactory;
import org.jdiameter.common.api.app.IAppSessionState;
import org.jdiameter.common.api.app.ro.IRoMessageFactory;
import org.jdiameter.common.api.app.ro.IRoSessionFactory;
import org.jdiameter.common.api.app.ro.IServerRoSessionContext;
import org.jdiameter.common.api.app.ro.ServerRoSessionState;
import org.jdiameter.common.impl.app.AppAnswerEventImpl;
import org.jdiameter.common.impl.app.AppRequestEventImpl;
import org.jdiameter.common.impl.app.auth.ReAuthAnswerImpl;
import org.jdiameter.common.impl.app.auth.ReAuthRequestImpl;
import org.jdiameter.common.impl.app.ro.AppRoSessionImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Credit Control Application Server session implementation
 * 
 * @author <a href="mailto:brainslog@gmail.com"> Alexandre Mendonca </a>
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class ServerRoSessionImpl extends AppRoSessionImpl implements ServerRoSession, NetworkReqListener, EventListener<Request, Answer> {

  private static final long serialVersionUID = 1L;
  private static final Logger logger = LoggerFactory.getLogger(ServerRoSessionImpl.class);

  // Session State Handling ---------------------------------------------------
  protected boolean stateless = true;
  protected ServerRoSessionState state = ServerRoSessionState.IDLE;
  protected Lock sendAndStateLock = new ReentrantLock();

  // Factories and Listeners --------------------------------------------------
  protected transient IRoMessageFactory factory = null;
  protected transient IServerRoSessionContext context = null;
  protected transient ServerRoSessionListener listener = null;

  //  Tcc timer (supervises an ongoing credit-control
  //             session in the credit-control server) ------------------------
  //protected transient ScheduledFuture tccFuture = null;
  protected Serializable tccTimerId;
  protected static final String TCC_TIMER_NAME = "TCC_RoSERVER_TIMER";

  protected long[] authAppIds = new long[]{4};
  protected String originHost, originRealm;

  public ServerRoSessionImpl(IRoMessageFactory fct, SessionFactory sf, ServerRoSessionListener lst, IServerRoSessionContext ctx,StateChangeListener<AppSession> stLst) {
    this(null, fct, sf, lst,ctx,stLst);
  }

  public ServerRoSessionImpl(String sessionId, IRoMessageFactory fct, SessionFactory sf, ServerRoSessionListener lst, IServerRoSessionContext ctx, StateChangeListener<AppSession> stLst) {
    super(sf,sessionId);
    if (lst == null) {
      throw new IllegalArgumentException("Listener can not be null");
    }
    if (fct.getApplicationIds() == null) {
      throw new IllegalArgumentException("ApplicationId can not be less than zero");
    }

    context = ctx;

    authAppIds = fct.getApplicationIds();
    listener = lst;
    factory = fct;
    super.addStateChangeNotification(stLst);
  }

  public void sendCreditControlAnswer(RoCreditControlAnswer answer) throws InternalException, IllegalDiameterStateException, RouteException, OverloadException {
    try {
      handleEvent(new Event(false, null, answer));
    } catch (AvpDataException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }

  public void sendReAuthRequest(ReAuthRequest request) throws InternalException, IllegalDiameterStateException, RouteException, OverloadException {
    send(Event.Type.SENT_RAR, request, null);
  }

  public boolean isStateless() {
    return stateless;
  }

  @SuppressWarnings("unchecked")
  public <E> E getState(Class<E> stateType) {
    return stateType == ServerRoSessionState.class ? (E) state : null;
  }

  public boolean handleEvent(StateEvent event) throws InternalException, OverloadException {
    ServerRoSessionState newState = null;

    try {
      sendAndStateLock.lock();

      // Can be null if there is no state transition, transition to IDLE state should terminate this app session
      Event localEvent = (Event) event;

      //Its kind of awkward, but with two state on server side its easier to go through event types?
      //but for sake of FSM readability
      Event.Type eventType = (Event.Type) localEvent.getType();
      switch(state)
      {
      case IDLE:
        switch(eventType)
        {
        case RECEIVED_INITIAL:
          listener.doCreditControlRequest(this, (RoCreditControlRequest)localEvent.getRequest());
          break;

        case RECEIVED_EVENT:
          // Current State: IDLE
          // Event: CC event request received and successfully processed
          // Action: Send CC event answer
          // New State: IDLE
          listener.doCreditControlRequest(this, (RoCreditControlRequest)localEvent.getRequest());
          break;

        case SENT_EVENT_RESPONSE:
          // Current State: IDLE
          // Event: CC event request received and successfully processed
          // Action: Send CC event answer
          // New State: IDLE

          // Current State: IDLE
          // Event: CC event request received but not successfully processed
          // Action: Send CC event answer with Result-Code != SUCCESS
          // New State: IDLE
          newState = ServerRoSessionState.IDLE;
          dispatchEvent(localEvent.getAnswer());
          break;

        case SENT_INITIAL_RESPONSE:
          RoCreditControlAnswer answer = (RoCreditControlAnswer) localEvent.getAnswer();
          try {
            long resultCode = answer.getResultCodeAvp().getUnsigned32();
            // Current State: IDLE
            // Event: CC initial request received and successfully processed
            // Action: Send CC initial answer, reserve units, start Tcc
            // New State: OPEN
            if(isSuccess(resultCode)) {
              startTcc(answer.getValidityTimeAvp());
              newState = ServerRoSessionState.OPEN;
            }
            // Current State: IDLE
            // Event: CC initial request received but not successfully processed
            // Action: Send CC initial answer with Result-Code != SUCCESS
            // New State: IDLE
            else {
              newState = ServerRoSessionState.IDLE;
            }
            dispatchEvent(localEvent.getAnswer());
          }
          catch (AvpDataException e) {
            throw new InternalException(e);
          }
          break;
        default:
          throw new InternalException("Wrong state: " + ServerRoSessionState.IDLE + " one event: " + eventType + " " + localEvent.getRequest() + " " + localEvent.getAnswer());
        }

      case OPEN:
        switch(eventType)
        {
        /* This should not happen, it should be silently discarded, right?
        case RECEIVED_INITIAL:
          // only for rtr
          if(((RoRequest)localEvent.getRequest()).getMessage().isReTransmitted()) {
            listener.doCreditControlRequest(this, (RoRequest)localEvent.getRequest());
          }
          else {
            //do nothing?
          }
          break;
         */
        case RECEIVED_UPDATE:
          listener.doCreditControlRequest(this, (RoCreditControlRequest)localEvent.getRequest());
          break;

        case SENT_UPDATE_RESPONSE:
          RoCreditControlAnswer answer = (RoCreditControlAnswer) localEvent.getAnswer();
          try {
            if(isSuccess(answer.getResultCodeAvp().getUnsigned32())) {
              // Current State: OPEN
              // Event: CC update request received and successfully processed
              // Action: Send CC update answer, debit used units, reserve new units, restart Tcc
              // New State: OPEN
              startTcc(answer.getValidityTimeAvp());
            }
            else {
              // Current State: OPEN
              // Event: CC update request received but not successfully processed
              // Action: Send CC update answer with Result-Code != SUCCESS, debit used units
              // New State: IDLE

              // It's a failure, we wait for Tcc to fire -- FIXME: Alexandre: Should we?
            }
          }
          catch (AvpDataException e) {
            throw new InternalException(e);
          }
          dispatchEvent(localEvent.getAnswer());
          break;
        case RECEIVED_TERMINATE:
          listener.doCreditControlRequest(this, (RoCreditControlRequest)localEvent.getRequest());
          break;
        case SENT_TERMINATE_RESPONSE:
          answer = (RoCreditControlAnswer) localEvent.getAnswer();
          try {
            // Current State: OPEN
            // Event: CC termination request received and successfully processed
            // Action: Send CC termination answer, Stop Tcc, debit used units
            // New State: IDLE
            if(isSuccess(answer.getResultCodeAvp().getUnsigned32())) {
              stopTcc(false);
            }
            else {
              // Current State: OPEN
              // Event: CC termination request received but not successfully processed
              // Action: Send CC termination answer with Result-Code != SUCCESS, debit used units
              // New State: IDLE

              // It's a failure, we wait for Tcc to fire -- FIXME: Alexandre: Should we?
            }
          }
          catch (AvpDataException e) {
            throw new InternalException(e);
          }
          finally {
            newState = ServerRoSessionState.IDLE;
          }
          dispatchEvent(localEvent.getAnswer());
          break;

        case RECEIVED_RAA:
          listener.doReAuthAnswer(this, new ReAuthRequestImpl(localEvent.getRequest().getMessage()), new ReAuthAnswerImpl(localEvent.getAnswer().getMessage()));
          break;
        case SENT_RAR:
          dispatchEvent(localEvent.getAnswer());
          break;
        }
      }
      return true;
    }
    catch (Exception e) {
      throw new InternalException(e);
    }
    finally {
      if(newState != null) {
        setState(newState);
      }
      sendAndStateLock.unlock();
    }
  }

  /*
   * (non-Javadoc)
   * 
   * @see org.jdiameter.common.impl.app.AppSessionImpl#isReplicable()
   */
  @Override
  public boolean isReplicable() {
    return true;
  }

  /*
   * (non-Javadoc)
   * 
   * @see org.jdiameter.common.impl.app.AppSessionImpl#relink(org.jdiameter.client.api.IContainer)
   */
  @Override
  public void relink(IContainer stack) {
    if (super.sf == null) {
      super.relink(stack);

      // hack this will change
      IRoSessionFactory fct = (IRoSessionFactory) ((ISessionFactory) super.sf).getAppSessionFactory(ServerRoSession.class);

      this.listener = fct.getServerSessionListener();
      this.context = fct.getServerContextListener();
      this.factory = fct.getMessageFactory();
    }
  }

  private class TccScheduledTask implements Runnable {
    ServerRoSession session = null;

    private TccScheduledTask(ServerRoSession session) {
      super();
      this.session = session;
    }

    public void run() {
      // Current State: OPEN
      // Event: Session supervision timer Tcc expired
      // Action: Release reserved units
      // New State: IDLE
      context.sessionSupervisionTimerExpired(session);
      try {
        sendAndStateLock.lock();
        // tccFuture = null;
        tccTimerId = null;
        setState(ServerRoSessionState.IDLE);
      }
      finally {
        sendAndStateLock.unlock();
      }
    }
  }

  public Answer processRequest(Request request) {
    RequestDelivery rd = new RequestDelivery();
    //rd.session = (ServerRoSession) LocalDataSource.INSTANCE.getSession(request.getSessionId());
    rd.session = this;
    rd.request = request;
    super.scheduler.execute(rd);
    return null;
  }

  public void receivedSuccessMessage(Request request, Answer answer) {
    AnswerDelivery rd = new AnswerDelivery();
    rd.session = this;
    rd.request = request;
    rd.answer = answer;
    super.scheduler.execute(rd);
  }

  public void timeoutExpired(Request request) {
    context.timeoutExpired(request);
    //FIXME: Should we release ?
  }

  private void startTcc(Avp validityAvp) {
    // There is no Validity-Time
    //long tccTimeout;
    //
    //if(validityAvp != null) {
    //  try {
    //    tccTimeout = 2 * validityAvp.getUnsigned32();
    //  }
    //  catch (AvpDataException e) {
    //    logger.debug("Unable to retrieve Validity-Time AVP value, using default.", e);
    //    tccTimeout = 2 * context.getDefaultValidityTime();
    //  }
    //}
    //else {
    //  tccTimeout = 2 * context.getDefaultValidityTime();
    //}
    //
    //if(tccTimerId != null) {
    //  stopTcc(true);
    //  //tccFuture = super.scheduler.schedule(new TccScheduledTask(this), defaultValue, TimeUnit.SECONDS);
    //  tccTimerId = super.timerFacility.schedule(this.sessionId, TCC_TIMER_NAME, tccTimeout * 1000);
    //  // FIXME: this accepts Future!
    //  context.sessionSupervisionTimerReStarted(this, null);
    //}
    //else {
    //  //tccFuture = super.scheduler.schedule(new TccScheduledTask(this), defaultValue, TimeUnit.SECONDS);
    //  tccTimerId = super.timerFacility.schedule(this.sessionId, TCC_TIMER_NAME, tccTimeout * 1000);
    //  //FIXME: this accepts Future!
    //  context.sessionSupervisionTimerStarted(this, null);
    //}
    //super.sessionDataSource.updateSession(this);
  }

  /*
   * (non-Javadoc)
   * 
   * @see org.jdiameter.common.impl.app.AppSessionImpl#onTimer(java.lang.String)
   */
  @Override
  public void onTimer(String timerName) {
    if (timerName.equals(TCC_TIMER_NAME)) {
      new TccScheduledTask(this).run();
    }
  }

  private void stopTcc(boolean willRestart) {
    if (tccTimerId != null) {
      // tccFuture.cancel(false);
      super.timerFacility.cancel(tccTimerId);
      // ScheduledFuture f = tccFuture;
      tccTimerId = null;
      if (!willRestart) {
        context.sessionSupervisionTimerStopped(this, null);
      }
      super.sessionDataSource.updateSession(this);
    }
  }

  protected  boolean isProvisional(long resultCode) {
    return resultCode >= 1000 && resultCode < 2000;
  }

  protected boolean isSuccess(long resultCode) {
    return resultCode >= 2000 && resultCode < 3000;
  }

  protected void setState(ServerRoSessionState newState) {
    setState(newState, true);
  }

  @SuppressWarnings("unchecked")
  protected void setState(ServerRoSessionState newState, boolean release) {
    IAppSessionState oldState = state;
    state = newState;

    for (StateChangeListener i : stateListeners) {
      i.stateChanged(this, (Enum) oldState, (Enum) newState);
    }
    if (newState == ServerRoSessionState.IDLE) {
      if (release) {
        this.release();
      }
      stopTcc(false);
    }
    else {
      super.sessionDataSource.updateSession(this);
    }
  }

  @SuppressWarnings("unchecked")
  @Override
  public void release() {
    this.stopTcc(false);

    if(super.isValid()) {
      super.release();
    }

    if(super.session != null) {
      super.session.setRequestListener(null);
    }

    this.session = null;

    if(listener != null) {
      this.removeStateChangeNotification((StateChangeListener) listener);
      this.listener = null;
    }

    this.factory = null;
  }

  protected void send(Event.Type type, AppRequestEvent request, AppAnswerEvent answer) throws InternalException {
    try {
      sendAndStateLock.lock();
      if (type != null) {
        handleEvent(new Event(type, request, answer));
      }
    }
    catch (Exception e) {
      throw new InternalException(e);
    }
    finally {
      sendAndStateLock.unlock();
    }
  }

  protected void dispatchEvent(AppEvent event) throws InternalException {
    try {
      session.send(event.getMessage(), this);
      // Store last destination information
      // FIXME: add differentiation on server/client request
      originRealm = event.getMessage().getAvps().getAvp(Avp.ORIGIN_REALM).getOctetString();
      originHost = event.getMessage().getAvps().getAvp(Avp.ORIGIN_HOST).getOctetString();
    }
    catch(Exception e) {
      //throw new InternalException(e);
      logger.debug("Failure trying to dispatch event", e);
    }
  }

  private class RequestDelivery implements Runnable {
    ServerRoSession session;
    Request request;

    public void run() {
      try {
        switch (request.getCommandCode()) {
        case RoCreditControlAnswer.code:
          handleEvent(new Event(true, factory.createCreditControlRequest(request), null));
          break;

        default:
          listener.doOtherEvent(session, new AppRequestEventImpl(request), null);
          break;
        }
      }
      catch (Exception e) {
        logger.debug("Failed to process request message", e);
      }
    }
  }

  private class AnswerDelivery implements Runnable {
    ServerRoSession session;
    Answer answer;
    Request request;

    public void run() {
      try {
        // FIXME: baranowb: add message validation here!!!
        // We handle CCR, STR, ACR, ASR other go into extension
        switch (request.getCommandCode()) {
        case ReAuthRequest.code:
          handleEvent(new Event(Event.Type.RECEIVED_RAA, factory.createReAuthRequest(request), factory.createReAuthAnswer(answer)));
          break;
        default:
          listener.doOtherEvent(session, new AppRequestEventImpl(request), new AppAnswerEventImpl(answer));
          break;
        }

      }
      catch (Exception e) {
        logger.debug("Failed to process success message", e);
      }
    }
  }

  /* (non-Javadoc)
   * @see java.lang.Object#hashCode()
   */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(authAppIds);
    result = prime * result + ((originHost == null) ? 0 : originHost.hashCode());
    result = prime * result + ((originRealm == null) ? 0 : originRealm.hashCode());
    result = prime * result + ((state == null) ? 0 : state.hashCode());
    result = prime * result + (stateless ? 1231 : 1237);
    return result;
  }

  /* (non-Javadoc)
   * @see java.lang.Object#equals(java.lang.Object)
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }

    ServerRoSessionImpl other = (ServerRoSessionImpl) obj;
    if (!Arrays.equals(authAppIds, other.authAppIds)) {
      return false;
    }
    if (originHost == null) {
      if (other.originHost != null) {
        return false;
      }
    }
    else if (!originHost.equals(other.originHost)) {
      return false;
    }
    if (originRealm == null) {
      if (other.originRealm != null) {
        return false;
      }
    }
    else if (!originRealm.equals(other.originRealm)) {
      return false;
    }
    if (state == null) {
      if (other.state != null) {
        return false;
      }
    }
    else if (!state.equals(other.state)) {
      return false;
    }
    if (stateless != other.stateless) {
      return false;
    }

    return true;
  }
  public String toString()
  {
    return super.toString()+" State[ "+state+" ] Timer[ "+tccTimerId+" ] Stateless[ "+stateless+" ]";
  }
}
