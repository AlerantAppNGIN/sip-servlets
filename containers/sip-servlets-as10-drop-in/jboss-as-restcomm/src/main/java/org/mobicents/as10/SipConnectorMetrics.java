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
package org.mobicents.as10;

import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceController;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.NAME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.mobicents.as10.SipMessages.MESSAGES;

/**
 * @author Emanuel Muckenhuber
 *
 *         This class is based on the contents of org.mobicents.as7 package from jboss-as7-mobicents project, re-implemented for
 *         jboss as10 (wildfly) by:
 * @author kakonyi.istvan@alerant.hu
 */
class SipConnectorMetrics implements OperationStepHandler {

    static SipConnectorMetrics INSTANCE = new SipConnectorMetrics();

    protected static final SimpleAttributeDefinition BYTES_SENT = new SimpleAttributeDefinitionBuilder(
            org.mobicents.as10.Constants.BYTES_SENT, ModelType.INT, true).setStorageRuntime().build();

    protected static final SimpleAttributeDefinition BYTES_RECEIVED = new SimpleAttributeDefinitionBuilder(
            org.mobicents.as10.Constants.BYTES_RECEIVED, ModelType.INT, true).setStorageRuntime().build();
    protected static final SimpleAttributeDefinition PROCESSING_TIME = new SimpleAttributeDefinitionBuilder(
            org.mobicents.as10.Constants.PROCESSING_TIME, ModelType.INT, true).setStorageRuntime().build();
    protected static final SimpleAttributeDefinition ERROR_COUNT = new SimpleAttributeDefinitionBuilder(
            org.mobicents.as10.Constants.ERROR_COUNT, ModelType.INT, true).setStorageRuntime().build();

    protected static final SimpleAttributeDefinition MAX_TIME = new SimpleAttributeDefinitionBuilder(
            org.mobicents.as10.Constants.MAX_TIME, ModelType.INT, true).setStorageRuntime().build();
    protected static final SimpleAttributeDefinition REQUEST_COUNT = new SimpleAttributeDefinitionBuilder(
            org.mobicents.as10.Constants.REQUEST_COUNT, ModelType.INT, true).setStorageRuntime().build();

    @Deprecated
    static final String[] ATTRIBUTES_OLD = { org.mobicents.as10.Constants.BYTES_SENT,
            org.mobicents.as10.Constants.BYTES_RECEIVED, org.mobicents.as10.Constants.PROCESSING_TIME,
            org.mobicents.as10.Constants.ERROR_COUNT, org.mobicents.as10.Constants.MAX_TIME,
            org.mobicents.as10.Constants.REQUEST_COUNT };
    static final SimpleAttributeDefinition[] ATTRIBUTES = {
            BYTES_SENT,
            BYTES_RECEIVED,
            PROCESSING_TIME,
            ERROR_COUNT,
            MAX_TIME,
            REQUEST_COUNT
    };

    @Override
    public void execute(OperationContext context, ModelNode operation) throws OperationFailedException {
        if (context.isNormalServer()) {
            context.addStep(new OperationStepHandler() {
                @Override
                public void execute(OperationContext context, ModelNode operation) throws OperationFailedException {
                    final PathAddress address = PathAddress.pathAddress(operation.require(OP_ADDR));
                    final String name = address.getLastElement().getValue();
                    final String attributeName = operation.require(NAME).asString();

                    final ServiceController<?> controller = context.getServiceRegistry(false).getService(
                            SipSubsystemServices.JBOSS_SIP_CONNECTOR.append(name));
                    if (controller != null) {
                        try {
                            final SipConnectorListener connector = (SipConnectorListener) controller.getValue();
                            final ModelNode result = context.getResult();
                            if (connector.getProtocolHandler() != null /*
                                                                        * FIXME:&&
                                                                        * connector.getProtocolHandler().getRequestGroupInfo()
                                                                        * != null
                                                                        */) {
                                // FIXME: kakonyii: currently there is no requestGroupInfo in SipProtocolHandler, so we need to
                                // find other solution to implement this:
                                // RequestGroupInfo info =
                                // connector.getProtocolHandler().getRequestGroupInfo();
                                // if (org.mobicents.as10.Constants.BYTES_SENT.equals(attributeName)) {
                                // result.set("" + info.getBytesSent());
                                // } else if (org.mobicents.as10.Constants.BYTES_RECEIVED.equals(attributeName)) {
                                // result.set("" + info.getBytesReceived());
                                // } else if (org.mobicents.as10.Constants.PROCESSING_TIME.equals(attributeName)) {
                                // result.set("" + info.getProcessingTime());
                                // } else if (org.mobicents.as10.Constants.ERROR_COUNT.equals(attributeName)) {
                                // result.set("" + info.getErrorCount());
                                // } else if (org.mobicents.as10.Constants.MAX_TIME.equals(attributeName)) {
                                // result.set("" + info.getMaxTime());
                                // } else if (org.mobicents.as10.Constants.REQUEST_COUNT.equals(attributeName)) {
                                // result.set("" + info.getRequestCount());
                                // }

                            }
                        } catch (Exception e) {
                            throw new OperationFailedException(new ModelNode().set(MESSAGES.failedToGetMetrics(e.getMessage())));
                        }
                    } else {
                        context.getResult().set(MESSAGES.noMetricsAvailable());
                    }
                    context.completeStep(OperationContext.RollbackHandler.NOOP_ROLLBACK_HANDLER);
                }
            }, OperationContext.Stage.RUNTIME);
        } else {
            context.getResult().set(MESSAGES.noMetricsAvailable());
        }
        context.completeStep(OperationContext.RollbackHandler.NOOP_ROLLBACK_HANDLER);
    }
}
