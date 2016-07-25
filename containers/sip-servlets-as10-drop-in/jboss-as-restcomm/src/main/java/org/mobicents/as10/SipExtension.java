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

import org.jboss.as.controller.Extension;
import org.jboss.as.controller.ExtensionContext;
import org.jboss.as.controller.ModelVersion;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.SubsystemRegistration;
import org.jboss.as.controller.descriptions.StandardResourceDescriptionResolver;
import org.jboss.as.controller.operations.common.GenericSubsystemDescribeHandler;
import org.jboss.as.controller.parsing.ExtensionParsingContext;
import org.jboss.as.controller.registry.ManagementResourceRegistration;

/**
 * The sip extension.
 *
 * @author Emanuel Muckenhuber
 * @author josemrecio@gmail.com
 *
 *         This class is based on the contents of org.mobicents.as7 package from jboss-as7-mobicents project, re-implemented for
 *         jboss as10 (wildfly) by:
 * @author kakonyi.istvan@alerant.hu
 * @author balogh.gabor@alerant.hu
 */
public class SipExtension implements Extension {
    public static final String SUBSYSTEM_NAME = "sip";
    public static final PathElement CONNECTOR_PATH = PathElement.pathElement(Constants.CONNECTOR);

    private static final String RESOURCE_NAME = SipExtension.class.getPackage().getName() + ".LocalDescriptions";

    public static StandardResourceDescriptionResolver getResourceDescriptionResolver(final String keyPrefix) {
        String prefix = SUBSYSTEM_NAME + (keyPrefix == null ? "" : "." + keyPrefix);
        return new StandardResourceDescriptionResolver(prefix, RESOURCE_NAME, SipExtension.class.getClassLoader(), true, false);
    }

    private static final int MANAGEMENT_API_MAJOR_VERSION = 1;
    private static final int MANAGEMENT_API_MINOR_VERSION = 1;

    /** {@inheritDoc} */
    @Override
    public void initialize(ExtensionContext context) {

        // final boolean registerRuntimeOnly = context.isRuntimeOnlyRegistrationValid();

        final SubsystemRegistration subsystem = context.registerSubsystem(SUBSYSTEM_NAME, ModelVersion.create(MANAGEMENT_API_MAJOR_VERSION,
                MANAGEMENT_API_MINOR_VERSION));
        
        final ManagementResourceRegistration registration = subsystem.registerSubsystemModel(SipDefinition.INSTANCE);
        registration.registerOperationHandler(GenericSubsystemDescribeHandler.DEFINITION, GenericSubsystemDescribeHandler.INSTANCE);               
        
        // final ManagementResourceRegistration registration =
        // subsystem.registerSubsystemModel(SipSubsystemDescriptionProviders.SUBSYSTEM);
        // registration.registerOperationHandler(ADD, SipSubsystemAdd.INSTANCE, SipSubsystemAdd.INSTANCE, false);
        // registration.registerOperationHandler(DESCRIBE, SipSubsystemDescribe.INSTANCE, SipSubsystemDescribe.INSTANCE, false,
        // OperationEntry.EntryType.PRIVATE);
        // registration.registerOperationHandler(REMOVE, ReloadRequiredRemoveStepHandler.INSTANCE,
        // SipSubsystemDescriptionProviders.SUBSYSTEM_REMOVE, false);
        subsystem.registerXMLElementWriter(SipSubsystemParser.getInstance());

        // connectors
        final ManagementResourceRegistration connectors = registration.registerSubModel(SipConnectorDefinition.INSTANCE);
        // final ManagementResourceRegistration connectors = registration.registerSubModel(CONNECTOR_PATH,
        // SipSubsystemDescriptionProviders.CONNECTOR);
        // connectors.registerOperationHandler(ADD, SipConnectorAdd.INSTANCE, SipConnectorAdd.INSTANCE, false);
        // connectors.registerOperationHandler(REMOVE, SipConnectorRemove.INSTANCE, SipConnectorRemove.INSTANCE, false);
        // if (registerRuntimeOnly) {
        // for (final String attributeName : SipConnectorMetrics.ATTRIBUTES) {
        // connectors.registerMetric(attributeName, SipConnectorMetrics.INSTANCE);
        // }
        // }
        // connectors.registerReadWriteAttribute(Constants.PROTOCOL, null, new
        // WriteAttributeHandlers.StringLengthValidatingHandler(1, true), Storage.CONFIGURATION);
        // connectors.registerReadWriteAttribute(Constants.SCHEME, null, new
        // WriteAttributeHandlers.StringLengthValidatingHandler(1, true), Storage.CONFIGURATION);
        // connectors.registerReadWriteAttribute(Constants.SOCKET_BINDING, null, new
        // WriteAttributeHandlers.StringLengthValidatingHandler(1), Storage.CONFIGURATION);
        // connectors.registerReadWriteAttribute(Constants.ENABLED, null, new
        // WriteAttributeHandlers.ModelTypeValidatingHandler(ModelType.BOOLEAN, true), Storage.CONFIGURATION);

        // deployment
        final ManagementResourceRegistration deployments = subsystem.registerDeploymentModel(SipDeploymentDefinition.INSTANCE);
        deployments.registerSubModel(SipDeploymentServletDefinition.INSTANCE);

        // if (registerRuntimeOnly) {
        // final ManagementResourceRegistration deployments =
        // subsystem.registerDeploymentModel(SipSubsystemDescriptionProviders.DEPLOYMENT);
        // final ManagementResourceRegistration servlets = deployments.registerSubModel(PathElement.pathElement("servlet"),
        // SipSubsystemDescriptionProviders.SERVLET);
        // ServletDeploymentStats.register(servlets);
        // }
    }

    /** {@inheritDoc} */
    @Override
    public void initializeParsers(ExtensionParsingContext context) {
        context.setSubsystemXmlMapping(SUBSYSTEM_NAME, Namespace.SIP_1_0.getUriString(), SipSubsystemParser.getInstance());
    }

}
