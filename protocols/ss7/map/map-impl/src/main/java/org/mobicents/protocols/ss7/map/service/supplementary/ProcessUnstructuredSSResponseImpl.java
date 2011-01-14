package org.mobicents.protocols.ss7.map.service.supplementary;

import org.mobicents.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.USSDString;

public class ProcessUnstructuredSSResponseImpl extends USSDServiceImpl
		implements ProcessUnstructuredSSResponse {

	public ProcessUnstructuredSSResponseImpl(byte ussdDataCodingSch,
			USSDString ussdString) {
		super(ussdDataCodingSch, ussdString);
	}

}
