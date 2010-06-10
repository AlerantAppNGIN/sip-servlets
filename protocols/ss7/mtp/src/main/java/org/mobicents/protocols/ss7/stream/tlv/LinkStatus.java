package org.mobicents.protocols.ss7.stream.tlv;

public enum LinkStatus{

	LinkUp((byte)1),LinkDown((byte)0);
	
	private byte status;

	LinkStatus(byte b)
	{
		this.status = b;
	}

	/**
	 * @return the status
	 */
	public byte getStatus() {
		return status;
	}
	
	public LinkStatus getFromByte(byte b)
	{
		if(b == 1)
		{
			return LinkUp;
			
		}else if(b == 0)
		{
			return LinkDown;
		}else
		{
			throw new IllegalArgumentException("No state associated with: "+b);
		}
	}
}
