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
package org.mobicents.as10.deployment;

import org.jboss.as.server.deployment.DeploymentPhaseContext;
import org.jboss.as.server.deployment.DeploymentUnit;
import org.jboss.as.server.deployment.DeploymentUnitProcessingException;
import org.jboss.as.server.deployment.DeploymentUnitProcessor;
import org.jboss.logging.Logger;
import org.mobicents.metadata.sip.spec.SipAnnotationMetaData;
import org.mobicents.metadata.sip.spec.SipMetaData;

/**
 * The SIP contextFactory deployment process will attach a {@code WebContextFactory} to the {@code DeploymentUnit} in case it
 * finds a SIP deployment.
 *
 * @author Emanuel Muckenhuber
 * @author josemrecio@gmail.com
 *
 *         This class is based on the contents of org.mobicents.as7.deployment package from jboss-as7-mobicents project,
 *         re-implemented for jboss as10 (wildfly) by:
 * @author kakonyi.istvan@alerant.hu
 */
public class SipContextFactoryDeploymentProcessor implements DeploymentUnitProcessor {

    private static final Logger logger = Logger.getLogger(SipContextFactoryDeploymentProcessor.class);
    public static final DeploymentUnitProcessor INSTANCE = new SipContextFactoryDeploymentProcessor();

    @Override
    public void deploy(final DeploymentPhaseContext phaseContext) throws DeploymentUnitProcessingException {

        final DeploymentUnit deploymentUnit = phaseContext.getDeploymentUnit();
        // Check if the deployment contains a sip metadata
        SipMetaData sipMetaData = deploymentUnit.getAttachment(SipMetaData.ATTACHMENT_KEY);
        if (sipMetaData == null) {
            if (logger.isDebugEnabled())
                logger.debug(deploymentUnit.getName() + " has null sipMetaData, checking annotations");
            SipAnnotationMetaData sipAnnotationMetaData = deploymentUnit.getAttachment(SipAnnotationMetaData.ATTACHMENT_KEY);
            if (sipAnnotationMetaData == null || !sipAnnotationMetaData.isSipApplicationAnnotationPresent()) {
                // http://code.google.com/p/sipservlets/issues/detail?id=168
                // When no sip.xml but annotations only, Application is not recognized as SIP App by AS7

                // In case there is no metadata attached, it means this is not a sip deployment, so we can safely ignore it!
                if (logger.isDebugEnabled())
                    logger.debug(deploymentUnit.getName()
                            + " has null sipMetaData and no SipApplication annotation, no Sip context factory installed");
                return;
            }
        }

        if (logger.isDebugEnabled())
            logger.debug(deploymentUnit.getName() + " sip context factory installed");
        // Just attach the context factory, the web subsystem will pick it up
        final SIPContextFactory contextFactory = new SIPContextFactory();
        deploymentUnit.putAttachment(SIPContextFactory.ATTACHMENT, contextFactory);
    }

    @Override
    public void undeploy(DeploymentUnit context) {
        //
    }
}
