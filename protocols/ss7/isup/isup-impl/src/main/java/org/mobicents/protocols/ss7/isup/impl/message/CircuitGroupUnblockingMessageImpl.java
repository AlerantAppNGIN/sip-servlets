/*
 * JBoss, Home of Professional Open Source
 * Copyright 2011, Red Hat, Inc. and individual contributors
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

package org.mobicents.protocols.ss7.isup.impl.message;

import java.util.Map;
import java.util.Set;

import org.mobicents.protocols.ss7.isup.ParameterRangeInvalidException;
import org.mobicents.protocols.ss7.isup.TransactionKey;
import org.mobicents.protocols.ss7.isup.impl.message.parameter.CircuitGroupSuperVisionMessageTypeImpl;
import org.mobicents.protocols.ss7.isup.impl.message.parameter.CircuitIdentificationCodeImpl;
import org.mobicents.protocols.ss7.isup.impl.message.parameter.MessageTypeImpl;
import org.mobicents.protocols.ss7.isup.impl.message.parameter.RangeAndStatusImpl;
import org.mobicents.protocols.ss7.isup.message.CircuitGroupUnblockingMessage;
import org.mobicents.protocols.ss7.isup.message.parameter.CircuitGroupSuperVisionMessageType;
import org.mobicents.protocols.ss7.isup.message.parameter.MessageType;
import org.mobicents.protocols.ss7.isup.message.parameter.RangeAndStatus;

/**
 * Start time:00:08:38 2009-09-07<br>
 * Project: mobicents-isup-stack<br>
 * 
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public class CircuitGroupUnblockingMessageImpl extends ISUPMessageImpl implements CircuitGroupUnblockingMessage {

	public static final MessageType _MESSAGE_TYPE = new MessageTypeImpl(MESSAGE_CODE);
	private static final int _MANDATORY_VAR_COUNT = 1;
	
	static final int _INDEX_F_MessageType = 0;
	static final int _INDEX_F_CircuitGroupSupervisionMessageType = 1;

	static final int _INDEX_V_RangeAndStatus = 0;

	//default, ident part of tx.
	static final String IDENT="CGU";
	
	CircuitGroupUnblockingMessageImpl(Object source, byte[] b, Set<Integer> mandatoryCodes, Set<Integer> mandatoryVariableCodes, Set<Integer> optionalCodes, Map<Integer, Integer> mandatoryCode2Index,
			Map<Integer, Integer> mandatoryVariableCode2Index, Map<Integer, Integer> optionalCode2Index) throws ParameterRangeInvalidException {
		this(source, mandatoryCodes, mandatoryVariableCodes, optionalCodes, mandatoryCode2Index, mandatoryVariableCode2Index, optionalCode2Index);
		decodeElement(b);

	}

	CircuitGroupUnblockingMessageImpl(Object source, Set<Integer> mandatoryCodes, Set<Integer> mandatoryVariableCodes, Set<Integer> optionalCodes, Map<Integer, Integer> mandatoryCode2Index,
			Map<Integer, Integer> mandatoryVariableCode2Index, Map<Integer, Integer> optionalCode2Index) {
		super(source, mandatoryCodes, mandatoryVariableCodes, optionalCodes, mandatoryCode2Index, mandatoryVariableCode2Index, optionalCode2Index);

		super.f_Parameters.put(_INDEX_F_MessageType, this.getMessageType());

	}

	public TransactionKey generateTransactionKey() {
		if(cic == null)
		{
			throw new NullPointerException("CIC is not set in message");
		}
		TransactionKey tk = new TransactionKey(IDENT,this.cic.getCIC());
		return tk;
	}
	
	public void setSupervisionType(CircuitGroupSuperVisionMessageType ras)
	{
		super.f_Parameters.put(_INDEX_F_CircuitGroupSupervisionMessageType,ras);
	}
	public CircuitGroupSuperVisionMessageType getSupervisionType()
	{
		return (CircuitGroupSuperVisionMessageType) super.f_Parameters.get(_INDEX_F_CircuitGroupSupervisionMessageType);
	}
	public void setRangeAndStatus(RangeAndStatus ras)
	{
		super.v_Parameters.put(_INDEX_V_RangeAndStatus, ras);
	}
	public RangeAndStatus getRangeAndStatus()
	{
		return (RangeAndStatus) super.v_Parameters.get(_INDEX_V_RangeAndStatus);
	}
	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.isup.ISUPMessageImpl#decodeMandatoryParameters(byte[],
	 * int)
	 */
	@Override
	protected int decodeMandatoryParameters(byte[] b, int index) throws ParameterRangeInvalidException {
		int localIndex = index;
		if (b.length - index > 3) {

			try {
				byte[] cic = new byte[2];
				cic[0] = b[index++];
				cic[1] = b[index++];
				super.cic = new CircuitIdentificationCodeImpl();
				super.cic.decodeElement(cic);

			} catch (Exception e) {
				// AIOOBE or IllegalArg
				throw new ParameterRangeInvalidException("Failed to parse CircuitIdentificationCode due to: ", e);
			}
			try {
				// Message Type
				if (b[index] != this.MESSAGE_CODE) {
					throw new ParameterRangeInvalidException("Message code is not: " + this.MESSAGE_CODE);
				}
			} catch (Exception e) {
				// AIOOBE or IllegalArg
				throw new ParameterRangeInvalidException("Failed to parse MessageCode due to: ", e);
			}
			index++;
			CircuitGroupSuperVisionMessageType cgsvmt = new CircuitGroupSuperVisionMessageTypeImpl(new byte[] { b[index] });
			super.addParameter(cgsvmt);
			index++;
			return index - localIndex;
		} else {
			throw new IllegalArgumentException("byte[] must have atleast four octets");
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.isup.ISUPMessageImpl#decodeMandatoryVariableBody(byte
	 * [], int)
	 */
	@Override
	protected void decodeMandatoryVariableBody(byte[] parameterBody, int parameterIndex) throws ParameterRangeInvalidException {
		switch (parameterIndex) {
		case _INDEX_V_RangeAndStatus:
			RangeAndStatus ras = new RangeAndStatusImpl(parameterBody);
			this.addParameter(ras);
			break;
		default:
			throw new IllegalArgumentException("Unrecognized parameter index for mandatory variable part, index: " + parameterIndex);

		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.isup.ISUPMessageImpl#decodeOptionalBody(byte[],
	 * byte)
	 */
	@Override
	protected void decodeOptionalBody(byte[] parameterBody, byte parameterCode) throws ParameterRangeInvalidException {
		throw new ParameterRangeInvalidException("This message does not support optional parameters");

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.isup.ISUPMessageImpl#getMessageType()
	 */
	@Override
	public MessageType getMessageType() {
		return _MESSAGE_TYPE;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @seeorg.mobicents.protocols.ss7.isup.ISUPMessageImpl#
	 * getNumberOfMandatoryVariableLengthParameters()
	 */
	@Override
	protected int getNumberOfMandatoryVariableLengthParameters() {

		return _MANDATORY_VAR_COUNT;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.isup.ISUPMessageImpl#hasAllMandatoryParameters()
	 */
	@Override
	public boolean hasAllMandatoryParameters() {
		return super.f_Parameters.get(_INDEX_F_CircuitGroupSupervisionMessageType) != null && super.v_Parameters.get(_INDEX_V_RangeAndStatus) != null;
	}

	@Override
	protected boolean optionalPartIsPossible() {

		return false;
	}

}
