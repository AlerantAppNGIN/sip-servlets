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

import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageBundle;
import org.jboss.logging.Messages;
import org.jboss.vfs.VirtualFile;

/**
 * Date: 05.11.2011
 *
 * @author <a href="mailto:jperkins@redhat.com">James R. Perkins</a>
 *
 *         This class is based on the contents of org.mobicents.as7 package from jboss-as7-mobicents project, re-implemented for
 *         jboss as8 (wildfly) by:
 * @author kakonyi.istvan@alerant.hu
 */
@MessageBundle(projectCode = "MSS")
public interface SipMessages {

    /**
     * The messages
     */
    SipMessages MESSAGES = Messages.getBundle(SipMessages.class);

    @Message(id = 18002, value = "Failed to get metrics %s")
    String failedToGetMetrics(String reason);

    @Message(id = 18003, value = "No metrics available")
    String noMetricsAvailable();

    @Message(id = 18007, value = "Error starting web connector")
    String connectorStartError();

    @Message(id = 18008, value = "Null service value")
    IllegalStateException nullValue();

    @Message(id = 18009, value = "Error starting sip container")
    String errorStartingSip();

    @Message(id = 18026, value = "Failed to resolve module for deployment %s")
    String failedToResolveModule(VirtualFile deploymentRoot);

    @Message(id = 18027, value = "Failed to add Mobicents SIP deployment service")
    String failedToAddSipDeployment();

    @Message(id = 18043, value = "%s has the wrong component type, it cannot be used as a SIP component")
    RuntimeException wrongComponentType(String clazz);

    /**
     * A message indicating the metric is unknown.
     *
     * @param metric the unknown metric.
     *
     * @return the message.
     */
    @Message(id = 18098, value = "Unknown metric %s")
    String unknownMetric(Object metric);

}
