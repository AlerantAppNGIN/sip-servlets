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

package org.jdiameter.common.impl.app.sh;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.jdiameter.api.Answer;
import org.jdiameter.api.NetworkReqListener;
import org.jdiameter.api.Request;
import org.jdiameter.api.SessionFactory;
import org.jdiameter.api.acc.events.AccountAnswer;
import org.jdiameter.api.acc.events.AccountRequest;
import org.jdiameter.api.app.AppSession;
import org.jdiameter.api.app.StateChangeListener;
import org.jdiameter.api.app.StateMachine;
import org.jdiameter.client.api.IContainer;
import org.jdiameter.client.api.ISessionFactory;
import org.jdiameter.common.api.app.sh.IShSessionFactory;
import org.jdiameter.common.impl.app.AppSessionImpl;
import org.jdiameter.common.impl.app.acc.AccountAnswerImpl;
import org.jdiameter.common.impl.app.acc.AccountRequestImpl;

/**
 * 
 * @author <a href="mailto:brainslog@gmail.com"> Alexandre Mendonca </a>
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public abstract class ShSession extends AppSessionImpl implements NetworkReqListener, StateMachine {

  private static final long serialVersionUID = 1L;

  protected Lock sendAndStateLock = new ReentrantLock();

  @SuppressWarnings("unchecked")
  protected transient List<StateChangeListener> stateListeners = new CopyOnWriteArrayList<StateChangeListener>();

  public ShSession(SessionFactory sf,String sessionId) {
    super(sf,sessionId);
  }

  @SuppressWarnings("unchecked")
  public void addStateChangeNotification(StateChangeListener listener) {
    if (!stateListeners.contains(listener)) {
      stateListeners.add(listener);
    }
  }

  @SuppressWarnings("unchecked")
  public void removeStateChangeNotification(StateChangeListener listener) {
    stateListeners.remove(listener);
  }

  protected AccountRequest createAccountRequest(Request request) {
    return new AccountRequestImpl(request);
  }

  protected AccountAnswer createAccountAnswer(Answer answer) {
    return new AccountAnswerImpl(answer);
  }

  public void release() {
    //scheduler.shutdown();
    super.release();
  }

  @SuppressWarnings("unchecked")
  @Override
  public void relink(IContainer stack) {
    if (super.sf == null) {
      super.relink(stack);

      // FIXME Any better way to do this?
      Class interfaze = null;
      for(Class possibleInterface : this.getClass().getInterfaces()) {
        if(interfaze != null) {
          break;
        }
        for(Class appSessionInterface : possibleInterface.getInterfaces()) {
          if (appSessionInterface.equals(AppSession.class)) {
            interfaze = possibleInterface;
            break;
          }
        }
      }

      IShSessionFactory fct = (IShSessionFactory) ((ISessionFactory) super.sf).getAppSessionFactory(interfaze);
      this.stateListeners = new CopyOnWriteArrayList<StateChangeListener>();
      this.stateListeners.add(fct.getStateChangeListener());

    }
  }
}
