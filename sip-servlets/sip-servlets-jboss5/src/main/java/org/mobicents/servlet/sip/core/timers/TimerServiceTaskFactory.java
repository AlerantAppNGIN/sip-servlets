/*
 * JBoss, Home of Professional Open Source
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
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
package org.mobicents.servlet.sip.core.timers;

import org.jboss.web.tomcat.service.session.ClusteredSipManager;
import org.jboss.web.tomcat.service.session.distributedcache.spi.OutgoingDistributableSessionData;
import org.mobicents.timers.TimerTask;
import org.mobicents.timers.TimerTaskData;
import org.mobicents.timers.TimerTaskFactory;

/**
 * Allow to recreate a sip servlet timer task upon failover
 * 
 * @author jean.deruelle@gmail.com
 *
 */
public class TimerServiceTaskFactory implements TimerTaskFactory {
	
	private ClusteredSipManager<? extends OutgoingDistributableSessionData> sipManager;
	
	public TimerServiceTaskFactory(ClusteredSipManager<? extends OutgoingDistributableSessionData> sipManager) {
		this.sipManager = sipManager;
	}
	
	/* (non-Javadoc)
	 * @see org.mobicents.timers.TimerTaskFactory#newTimerTask(org.mobicents.timers.TimerTaskData)
	 */
	public TimerTask newTimerTask(TimerTaskData data) {		
		return new TimerServiceTask(sipManager, null, (TimerServiceTaskData)data);
	}

}
