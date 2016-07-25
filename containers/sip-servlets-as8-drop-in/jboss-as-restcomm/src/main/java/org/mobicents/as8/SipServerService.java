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
package org.mobicents.as8;

import static org.mobicents.as8.SipMessages.MESSAGES;

import javax.management.MBeanServer;

import org.jboss.as.controller.services.path.PathManager;
import org.jboss.logging.Logger;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.mobicents.servlet.sip.core.SipApplicationDispatcherImpl;
import org.mobicents.servlet.sip.undertow.SipProtocolHandler;
import org.mobicents.servlet.sip.undertow.SipStandardService;

/**
 * Service configuring and starting the web container.
 *
 * @author Emanuel Muckenhuber
 *
 *         This class is based on the contents of org.mobicents.as7 package from jboss-as7-mobicents project, re-implemented for
 *         jboss as8 (wildfly) by:
 * @author kakonyi.istvan@alerant.hu
 */
class SipServerService implements SipServer, Service<SipServer> {
    private static final Logger logger = Logger.getLogger(SipServerService.class);
    // FIXME: josemrecio - settle on using the proper name
    private static final String JBOSS_SIP = "jboss.sip";

    private static final String TEMP_DIR = "jboss.server.temp.dir";

    // private final String defaultHost;
    // private final boolean useNative;
    private static final String FILE_PREFIX_PATH = "file:///";
    private String sipAppRouterFile;
    private String sipStackPropertiesFile;
    final String sipPathName;
    final String sipAppDispatcherClass;
    final String additionalParameterableHeaders;
    final String proxyTimerServiceImplementationType;
    final String sasTimerServiceImplementationType;
    final int sipCongestionControlInterval;
    final String congestionControlPolicy;
    final String sipConcurrencyControlMode;
    final boolean usePrettyEncoding;
    final int baseTimerInterval;
    final int t2Interval;
    final int t4Interval;
    final int timerDInterval;
    final boolean dialogPendingRequestChecking;
    final String dnsServerLocatorClass;
    int dnsTimeout;
    final String dnsResolverClass;
    final int callIdMaxLength;
    final int tagHashMaxLength;
    final int canceledTimerTasksPurgePeriod;
    final int memoryThreshold;
    final int backToNormalMemoryThreshold;
    final String outboundProxy;

    private final String instanceId;

    // FIXME: kakonyii
    // private Engine engine;
    // private StandardServer server;
    // private StandardService service;

    // FIXME: kakonyii
    // private SipStandardEngine sipEngine;
    private SipStandardService sipService;

    private final InjectedValue<MBeanServer> mbeanServer = new InjectedValue<MBeanServer>();
    private final InjectedValue<PathManager> pathManagerInjector = new InjectedValue<PathManager>();

    public SipServerService(
            final String sipAppRouterFile,
            final String sipStackPropertiesFile,
            final String sipPathName,
            String sipAppDispatcherClass,
            String additionalParameterableHeaders,
            String proxyTimerServiceImplementationType,
            String sasTimerServiceImplementationType,
            int sipCongestionControlInterval,
            String congestionControlPolicy,
            String sipConcurrencyControlMode,
            boolean usePrettyEncoding,
            int baseTimerInterval,
            int t2Interval,
            int t4Interval,
            int timerDInterval,
            boolean dialogPendingRequestChecking,
            String dnsServerLocatorClass,
            int dnsTimeout,
            String dnsResolverClass,
            int callIdMaxLength,
            int tagHashMaxLength,
            int canceledTimerTasksPurgePeriod,
            int memoryThreshold,
            int backToNormalMemoryThreshold,
            String outboundProxy,
            String instanceId) {

        // FIXME: kakonyii
        // this.defaultHost = defaultHost;
        // this.useNative = useNative;
        this.sipAppRouterFile = sipAppRouterFile;
        this.sipStackPropertiesFile = sipStackPropertiesFile;
        this.sipPathName = sipPathName;
        this.sipAppDispatcherClass = sipAppDispatcherClass;
        this.additionalParameterableHeaders = additionalParameterableHeaders;
        this.proxyTimerServiceImplementationType = proxyTimerServiceImplementationType;
        this.sasTimerServiceImplementationType = sasTimerServiceImplementationType;
        this.sipCongestionControlInterval = sipCongestionControlInterval;
        this.congestionControlPolicy = congestionControlPolicy;
        this.sipConcurrencyControlMode = sipConcurrencyControlMode;
        this.instanceId = instanceId;
        this.usePrettyEncoding = usePrettyEncoding;
        this.baseTimerInterval = baseTimerInterval;
        this.t2Interval = t2Interval;
        this.t4Interval = t4Interval;
        this.timerDInterval = timerDInterval;
        this.dialogPendingRequestChecking = dialogPendingRequestChecking;
        this.dnsServerLocatorClass = dnsServerLocatorClass;
        this.dnsTimeout = dnsTimeout;
        this.dnsResolverClass = dnsResolverClass;
        this.callIdMaxLength = callIdMaxLength;
        this.tagHashMaxLength = tagHashMaxLength;
        this.canceledTimerTasksPurgePeriod = canceledTimerTasksPurgePeriod;
        this.memoryThreshold = memoryThreshold;
        this.backToNormalMemoryThreshold = backToNormalMemoryThreshold;
        this.outboundProxy = outboundProxy;
    }

    /** {@inheritDoc} */
    public synchronized void start(StartContext context) throws StartException {
        // FIXME: kakonyii
        // if (org.apache.tomcat.util.Constants.ENABLE_MODELER) {
        // Set the MBeanServer
        final MBeanServer mbeanServer = this.mbeanServer.getOptionalValue();
        if (mbeanServer != null) {
            // Registry.getRegistry(null, null).setMBeanServer(mbeanServer);
        }
        // }

        System.setProperty("catalina.home", pathManagerInjector.getValue().getPathEntry(TEMP_DIR).resolvePath());
        // FIXME: kakonyii
        // server = new StandardServer();
        // final StandardService service = new StandardService();
        // service.setName(JBOSS_SIP);
        // service.setServer(server);
        // server.addService(service);

        // final Engine engine = new StandardEngine();
        // engine.setName(JBOSS_SIP);
        // engine.setService(service);
        // engine.setDefaultHost(defaultHost);
        // if (instanceId != null) {
        // engine.setJvmRoute(instanceId);
        // }

        // service.setContainer(engine);

        // if (useNative) {
        // final AprLifecycleListener apr = new AprLifecycleListener();
        // apr.setSSLEngine("on");
        // server.addLifecycleListener(apr);
        // }
        // server.addLifecycleListener(new JasperListener());

        sipService = new SipStandardService();
        // https://code.google.com/p/sipservlets/issues/detail?id=277
        // Add the Service and sip app dispatched right away so apps can get the needed objects
        // when they deploy fast
        // FIXME: kakonyii
        // server.addService(sipService);

        if (sipAppDispatcherClass != null) {
            sipService.setSipApplicationDispatcherClassName(sipAppDispatcherClass);
        } else {
            sipService.setSipApplicationDispatcherClassName(SipApplicationDispatcherImpl.class.getName());
        }
        //
        final String baseDir = System.getProperty("jboss.server.base.dir");
        if (sipAppRouterFile != null) {
            if (!sipAppRouterFile.startsWith(FILE_PREFIX_PATH)) {
                sipAppRouterFile = FILE_PREFIX_PATH.concat(baseDir).concat("/").concat(sipAppRouterFile);
            }
            System.setProperty("javax.servlet.sip.dar", sipAppRouterFile);
        }

        sipService.setSipPathName(sipPathName);

        if (sipStackPropertiesFile != null) {
            if (!sipStackPropertiesFile.startsWith(FILE_PREFIX_PATH)) {
                sipStackPropertiesFile = FILE_PREFIX_PATH.concat(baseDir).concat("/").concat(sipStackPropertiesFile);
            }
        }
        sipService.setSipStackPropertiesFile(sipStackPropertiesFile);
        //
        if (sipConcurrencyControlMode != null) {
            sipService.setConcurrencyControlMode(sipConcurrencyControlMode);
        } else {
            sipService.setConcurrencyControlMode("None");
        }

        sipService.setProxyTimerServiceImplementationType(proxyTimerServiceImplementationType);
        sipService.setSasTimerServiceImplementationType(sasTimerServiceImplementationType);

        sipService.setCongestionControlCheckingInterval(sipCongestionControlInterval);

        sipService.setUsePrettyEncoding(usePrettyEncoding);

        sipService.setBaseTimerInterval(baseTimerInterval);
        sipService.setT2Interval(t2Interval);
        sipService.setT4Interval(t4Interval);
        sipService.setTimerDInterval(timerDInterval);
        if (additionalParameterableHeaders != null) {
            sipService.setAdditionalParameterableHeaders(additionalParameterableHeaders);
        }
        sipService.setDialogPendingRequestChecking(dialogPendingRequestChecking);
        sipService.setDnsServerLocatorClass(dnsServerLocatorClass);
        sipService.setCallIdMaxLength(callIdMaxLength);
        sipService.setTagHashMaxLength(tagHashMaxLength);
        sipService.setDnsTimeout(dnsTimeout);
        sipService.setDnsResolverClass(dnsResolverClass);
        sipService.setCanceledTimerTasksPurgePeriod(canceledTimerTasksPurgePeriod);
        sipService.setMemoryThreshold(memoryThreshold);
        sipService.setBackToNormalMemoryThreshold(backToNormalMemoryThreshold);
        sipService.setCongestionControlPolicy(congestionControlPolicy);
        sipService.setOutboundProxy(outboundProxy);
        sipService.setName(JBOSS_SIP);

        // FIXME: kakonyii
        // sipService.setServer(server);
        // sipEngine = new SipStandardEngine();
        // sipEngine.setName(JBOSS_SIP);
        // sipEngine.setService(sipService);
        // sipEngine.setDefaultHost(defaultHost);
        if (instanceId != null) {
            // sipEngine.setJvmRoute(instanceId);
        }
        // sipService.setContainer(sipEngine);

        try {
            sipService.initialize();
            sipService.start();
            // FIXME: kakonyii
            // server.init();
            // server.start();
        } catch (Exception e) {
            throw new StartException(MESSAGES.errorStartingSip(), e);
        }
    }

    /** {@inheritDoc} */
    @Override
    public synchronized void stop(StopContext context) {
        try {
            sipService.stop();
            // FIXME: kakonyii
            // server.stop();
        } catch (Exception e) {
        }
        // FIXME: kakonyii
        // engine = null;
        // service = null;
        // server = null;
        // sipEngine = null;
        sipService = null;
    }

    /** {@inheritDoc} */
    public synchronized SipServer getValue() throws IllegalStateException {
        return this;
    }

    /** {@inheritDoc} */
    public synchronized void addConnector(SipConnectorListener connector) {
        if (connector.getProtocolHandler() instanceof SipProtocolHandler) {
            final SipStandardService sipService = this.sipService;
            sipService.addConnector(connector.getProtocolHandler());
        }
    }

    /** {@inheritDoc} */
    public synchronized void removeConnector(SipConnectorListener connector) {
        if (connector.getProtocolHandler() instanceof SipProtocolHandler) {
            final SipStandardService service = this.sipService;
            service.removeConnector(connector.getProtocolHandler());
        }
    }

    /** {@inheritDoc} */
    // FIXME: kakonyii
    // public synchronized void addHost(Host host) {
    // final Engine engine = this.engine;
    // engine.addChild(host);
    // final SipStandardEngine sipEngine = this.sipEngine;
    // sipEngine.addChild(host);
    // }

    /** {@inheritDoc} */
    // FIXME: kakonyii
    // public synchronized void removeHost(Host host) {
    // final Engine engine = this.engine;
    // engine.removeChild(host);
    // final SipStandardEngine sipEngine = this.sipEngine;
    // sipEngine.removeChild(host);
    // }

    InjectedValue<MBeanServer> getMbeanServer() {
        return mbeanServer;
    }

    InjectedValue<PathManager> getPathManagerInjector() {
        return pathManagerInjector;
    }

    // FIXME: kakonyii
    // public StandardServer getServer() {
    // return server;
    // }

    // FIXME: kakonyii
    // public StandardService getService() {
    // return sipService;
    // }

    public SipStandardService getSipService() {
        return sipService;
    }

    @Override
    public SipStandardService getService() {
        return sipService;
    }

}
