/*
 * TeleStax, Open Source Cloud Communications
 * Copyright 2011-2015, Telestax Inc and individual contributors
 * by the @authors tag.
 *
 * This program is free software: you can redistribute it and/or modify
 * under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

package org.mobicents.servlet.sip.undertow;

import java.util.EventListener;

import javax.servlet.sip.annotation.SipServlet;

import org.apache.log4j.Logger;
import org.mobicents.servlet.sip.core.MobicentsSipServlet;
import org.mobicents.servlet.sip.core.SipContext;
import org.mobicents.servlet.sip.core.session.SipListenersHolder;

/**
 * @author jean.deruelle@gmail.com
 *
 *         This class is based on org.mobicents.servlet.sip.catalina.CatalinaSipListenersHolder class from sip-servlet-as7
 *         project, re-implemented for jboss as10 (wildfly) by:
 * @author kakonyi.istvan@alerant.hu
 *
 */
public class UndertowSipListenersHolder extends SipListenersHolder {

    private static final Logger logger = Logger.getLogger(UndertowSipListenersHolder.class);

    public UndertowSipListenersHolder(SipContext sipContext) {
        super(sipContext);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.servlet.sip.core.session.SipListenersHolder#loadListeners(java.lang.String[], java.lang.ClassLoader)
     */
    @Override
    public boolean loadListeners(String[] listeners, ClassLoader classLoader) {
        // Instantiate all the listeners
        for (String className : listeners) {
            try {
                Class listenerClass = Class.forName(className, false, classLoader);
                EventListener listener = (EventListener) listenerClass.newInstance();

                // copied from org.mobicents.servlet.sip.catalina.CatalinaSipListenersHolder, still need to fix this:
                // FIXME !!! SipInstanceManager sipInstanceManager = ((CatalinaSipContext)sipContext).getSipInstanceManager();
                // FIXME !! sipInstanceManager.processAnnotations(listener,
                // sipInstanceManager.getInjectionMap(listenerClass.getName()));

                MobicentsSipServlet sipServletImpl = (MobicentsSipServlet) sipContext.findSipServletByClassName(className);
                if (sipServletImpl != null) {
                    listener = (EventListener) sipServletImpl.allocate();
                    listenerServlets.put(listener, sipServletImpl);
                } else {
                    SipServlet servlet = (SipServlet) listenerClass.getAnnotation(SipServlet.class);
                    if (servlet != null) {
                        sipServletImpl = (MobicentsSipServlet) sipContext.findSipServletByName(servlet.name());
                        if (sipServletImpl != null) {
                            listener = (EventListener) sipServletImpl.allocate();
                            listenerServlets.put(listener, sipServletImpl);
                        }
                    }
                }
                addListenerToBunch(listener);
            } catch (Exception e) {
                logger.fatal("Cannot instantiate listener class " + className, e);
                return false;
            }
        }
        return true;
    }

}
