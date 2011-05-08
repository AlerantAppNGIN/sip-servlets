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

package org.mobicents.diameter.impl.ha.data;

import java.io.Serializable;

import org.jboss.cache.Fqn;
import org.jdiameter.api.BaseSession;
import org.jdiameter.api.NetworkReqListener;
import org.mobicents.cluster.MobicentsCluster;
import org.mobicents.cluster.cache.ClusteredCacheData;
import org.mobicents.diameter.api.ha.data.ISessionClusteredData;

/**
 * Basic implementation of clustered data
 * 
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 * @author <a href="mailto:brainslog@gmail.com"> Alexandre Mendonca </a>
 */
public class SessionClusteredData extends ClusteredCacheData implements ISessionClusteredData {

  final static String _SESSIONS = "/diameter/appsessions";
  @SuppressWarnings("unchecked")
  final static Fqn SESSIONS = Fqn.fromString(_SESSIONS);

  final static String SESSION_KEY = "session";
  final static String LISTENER_KEY = "lst";

  /**
   * @param nodeFqn
   * @param mobicentsCluster
   */
  public SessionClusteredData(Fqn<?> nodeFqn, MobicentsCluster mobicentsCluster) {
    super(nodeFqn, mobicentsCluster);
    // this is used by MobicentsCluster
  }

  @SuppressWarnings("unchecked")
  public SessionClusteredData(String sessionId, MobicentsCluster mobicentsCluster) {
    super(Fqn.fromRelativeElements(SESSIONS, sessionId), mobicentsCluster);
    // this is used by us to ease creation of this object :)
  }

  /*
   * (non-Javadoc)
   * 
   * @see org.mobicents.diameter.api.ha.data.ISessionClusteredData#getSession()
   */
  @SuppressWarnings("unchecked")
  public BaseSession getSession() {
    if (exists()) {
      return (BaseSession) getNode().get(SESSION_KEY);
    }
    else {
      // throw exception?
      return null;
    }
  }

  /*
   * (non-Javadoc)
   * 
   * @see org.mobicents.diameter.api.ha.data.ISessionClusteredData#getSessionListener()
   */
  @SuppressWarnings("unchecked")
  public NetworkReqListener getSessionListener() {
    if (exists()) {
      Serializable ser = (Serializable) getNode().get(LISTENER_KEY);
      if (ser instanceof ListenerRef) {
        ListenerRef lr = (ListenerRef) ser;
        return lr.getListener(this);
      }
      else {
        return (NetworkReqListener) ser;
      }
    }
    else {
      return null;
    }
  }

  /*
   * (non-Javadoc)
   * 
   * @see org.mobicents.diameter.api.ha.data.ISessionClusteredData#setSession(org.jdiameter.api.BaseSession)
   */
  @SuppressWarnings("unchecked")
  public void setSession(BaseSession session) {
    if (exists()) {
      getNode().put(SESSION_KEY, session);
    }
    else {
      // ?
    }
  }

  /*
   * (non-Javadoc)
   * 
   * @see org.mobicents.diameter.api.ha.data.ISessionClusteredData#setSessionListener(org.jdiameter.api.NetworkReqListener)
   */
  @SuppressWarnings("unchecked")
  public void setSessionListener(NetworkReqListener listener) {
    if (exists()) {
      BaseSession x = (BaseSession) getNode().get(SESSION_KEY);
      if (x.equals(listener)) {
        ListenerRef ref = new ListenerRef();
        getNode().put(LISTENER_KEY, ref);
      }
      else {
        getNode().put(LISTENER_KEY, listener);
      }
    }
    else {
      // ?
    }
  }

}