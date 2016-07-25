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
package org.mobicents.metadata.sip.spec;

import java.util.Collections;
import java.util.List;

import org.jboss.metadata.javaee.spec.EmptyMetaData;
import org.jboss.metadata.javaee.support.IdMetaDataImpl;
import org.jboss.metadata.web.spec.AuthConstraintMetaData;
import org.jboss.metadata.web.spec.TransportGuaranteeType;
import org.jboss.metadata.web.spec.UserDataConstraintMetaData;

/**
 * The sip app security-constraints
 *
 * @author jean.deruelle@gmail.com
 * @version $Revision$
 *
 *          This class is based on the contents of org.mobicents.metadata.sip.spec package from jboss-as7-mobicents project,
 *          re-implemented for jboss as10 (wildfly) by:
 * @author kakonyi.istvan@alerant.hu
 */
public class SipSecurityConstraintMetaData extends IdMetaDataImpl {
    private static final long serialVersionUID = 1;

    private String displayName;
    private SipResourceCollectionsMetaData resourceCollections;
    private EmptyMetaData proxyAuthentication;
    private AuthConstraintMetaData authConstraint;
    private UserDataConstraintMetaData userDataConstraint;

    public AuthConstraintMetaData getAuthConstraint() {
        return authConstraint;
    }

    public void setAuthConstraint(AuthConstraintMetaData authConstraint) {
        this.authConstraint = authConstraint;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public SipResourceCollectionsMetaData getResourceCollections() {
        return resourceCollections;
    }

    public void setResourceCollections(SipResourceCollectionsMetaData resourceCollections) {
        this.resourceCollections = resourceCollections;
    }

    public UserDataConstraintMetaData getUserDataConstraint() {
        return userDataConstraint;
    }

    public void setUserDataConstraint(UserDataConstraintMetaData userDataConstraint) {
        this.userDataConstraint = userDataConstraint;
    }

    /**
     * The unchecked flag is set when there is no security-constraint/auth-constraint
     *
     * @return true if there is no auth-constraint
     */
    // @XmlTransient
    public boolean isUnchecked() {
        return authConstraint == null;
    }

    /**
     * The excluded flag is set when there is an empty security-constraint/auth-constraint element
     *
     * @return true if there is an empty auth-constraint
     */
    // @XmlTransient
    public boolean isExcluded() {
        boolean isExcluded = authConstraint != null && authConstraint.getRoleNames() == null;
        return isExcluded;
    }

    /**
     * Accessor for the security-constraint/auth-constraint/role-name(s)
     *
     * @return A possibly empty set of constraint role names. Use isUnchecked and isExcluded to check for no or an emtpy
     *         auth-constraint
     */
    // @XmlTransient
    public List<String> getRoleNames() {
        List<String> roleNames = Collections.emptyList();
        if (authConstraint != null && authConstraint.getRoleNames() != null)
            roleNames = authConstraint.getRoleNames();
        return roleNames;
    }

    /**
     * Accessor for the UserDataConstraint.TransportGuarantee
     *
     * @return UserDataConstraint.TransportGuarantee
     */
    // @XmlTransient
    public TransportGuaranteeType getTransportGuarantee() {
        TransportGuaranteeType type = TransportGuaranteeType.NONE;
        if (userDataConstraint != null)
            type = userDataConstraint.getTransportGuarantee();
        return type;
    }

    /**
     * @param proxyAuthentication the proxyAuthentication to set
     */
    public void setProxyAuthentication(EmptyMetaData proxyAuthentication) {
        this.proxyAuthentication = proxyAuthentication;
    }

    /**
     * @return the proxyAuthentication
     */
    // @XmlTransient
    public EmptyMetaData getProxyAuthentication() {
        return proxyAuthentication;
    }
}
