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

package org.mobicents.servlet.sip.undertow.rules;

import javax.servlet.sip.SipServletRequest;

import org.mobicents.servlet.sip.core.descriptor.MatchingRule;

/**
 * @author Thomas Leseney
 *
 *         This class is based on the contents of org.mobicents.servlet.sip.catalina.rules package from sip-servlet-as7 project,
 *         re-implemented for jboss as10 (wildfly) by:
 * @author kakonyi.istvan@alerant.hu
 */
public class SubdomainRule extends RequestRule implements MatchingRule {

    private String value;

    public SubdomainRule(String var, String value) {
        super(var);
        this.value = value;
    }

    public boolean matches(SipServletRequest request) {
        String requestValue = getValue(request);
        if (requestValue == null) {
            return false;
        }
        if (requestValue.endsWith(value)) {
            int len1 = requestValue.length();
            int len2 = value.length();
            return (len1 == len2 || (requestValue.charAt(len1 - len2 - 1) == '.'));
        }
        return false;
    }

    public String getExpression() {
        return "(" + getVarName() + " subdomainOf " + value + ")";
    }
}
