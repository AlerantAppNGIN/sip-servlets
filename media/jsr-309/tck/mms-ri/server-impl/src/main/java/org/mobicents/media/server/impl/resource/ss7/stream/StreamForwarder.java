package org.mobicents.media.server.impl.resource.ss7.stream;

import java.net.UnknownHostException;

import org.mobicents.media.server.impl.resource.ss7.Mtp3;


/**
 * Interface for forwarding classes(TCP/SCTP)
 * @author baranowb
 *
 */
public interface StreamForwarder {

	public void setPort(int port);
	public int getPort();
	public void setAddress(String address) throws UnknownHostException;
	public String getAddress();
	
	public void setLayer3(Mtp3 layer3);
	public void setServiceIndicator(int i);
	public void setSubServiceIndicator(int i);
	public void start() throws Exception;
	public void stop();

}
