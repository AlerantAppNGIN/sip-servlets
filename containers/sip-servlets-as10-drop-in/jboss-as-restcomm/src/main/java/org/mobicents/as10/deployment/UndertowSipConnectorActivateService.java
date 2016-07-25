/*
 * TeleStax, Open Source Cloud Communications  Copyright 2012.
 * and individual contributors
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
package org.mobicents.as10.deployment;

import java.util.LinkedHashMap;
import java.util.Map;

import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.Mode;
import org.mobicents.as10.SipConnectorService;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;

/**
 * This service will start up and activate sip connector(s) AFTER all sip deployments finished in order to prevent the sip server to handle incoming messages before sip applications ready.
 *
 * @author kakonyi.istvan@alerant.hu
 */
public class UndertowSipConnectorActivateService implements Service<UndertowSipConnectorActivateService> {
    public static final ServiceName SERVICE_NAME = ServiceName.of("UndertowSipConnectorActivateService");

    private Map<ServiceName,ServiceController<SipConnectorService>> serviceControllers = null;

    public void addServiceController(ServiceController<SipConnectorService> serviceController){
        if(serviceControllers == null){
            serviceControllers = new LinkedHashMap<ServiceName,ServiceController<SipConnectorService>>();
        }
        this.serviceControllers.put(serviceController.getName(),serviceController);
    }

    public ServiceController<SipConnectorService> getServiceController(ServiceName serviceName){
        if(serviceControllers == null){
            return null;
        }
        return this.serviceControllers.get(serviceName);
    }

    @Override
    public UndertowSipConnectorActivateService getValue() throws IllegalStateException, IllegalArgumentException {
        return this;
    }

    @Override
    public void start(StartContext context) throws StartException {
        if(serviceControllers!=null){
            for(ServiceController<SipConnectorService> serviceController : serviceControllers.values()){
                //activate the sip connector:
                if(serviceController!=null && serviceController.getMode() != Mode.ACTIVE){
                    serviceController.setMode(Mode.ACTIVE);
                }
            }
        }
    }

    @Override
    public void stop(StopContext context) {
    }

}
