/*
 * JBoss, Home of Professional Open Source
 * Copyright XXXX, Red Hat Middleware LLC, and individual contributors as indicated
 * by the @authors tag. All rights reserved.
 * See the copyright.txt in the distribution for a full listing
 * of individual contributors.
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License, v. 2.0.
 * This program is distributed in the hope that it will be useful, but WITHOUT A
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License,
 * v. 2.0 along with this distribution; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */
package org.mobicents.media.server.impl.resource.ss7.stream;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.log4j.Logger;
import org.mobicents.media.server.impl.resource.ss7.FastHDLC;
import org.mobicents.media.server.impl.resource.ss7.HdlcState;
import org.mobicents.media.server.spi.resource.ss7.*;
import org.mobicents.media.server.spi.resource.ss7.stream.StreamForwarder;



public class SimpleTCPForwarder implements SS7Layer4, StreamForwarder, Runnable {
	private static final Logger logger = Logger.getLogger(SimpleTCPForwarder.class);
	private ExecutorService executor = Executors.newSingleThreadExecutor();
	private int port = 1354;
	private InetAddress address;
	private ServerSocketChannel serverSocketChannel;
	private SocketChannel channel;
	private Selector readSelector;
	private Selector writeSelector;
	private Selector connectSelector;
	// we accept only one connection
	private boolean connected = false;
	private ByteBuffer readBuff = ByteBuffer.allocate(8192);
	private ByteBuffer txBuff = ByteBuffer.allocate(8192);
	

	private Mtp3 layer3;
	private boolean linkUp = false;
	private Future runFuture;
	private int si;
	private int ssf;
	private HDLCHandler hdlcHandler = new HDLCHandler();
	//private LinkedList<ByteBuffer> txBuffer = new LinkedList<ByteBuffer>();
	
	
	             
	public SimpleTCPForwarder() {
		super();
		txBuff.position(txBuff.capacity());
	}

	// ///////////////
	// Server Side //
	// ///////////////


	public void run() {
		while (true) {
			try {

				Iterator selectedKeys = null;

				// Wait for an event one of the registered channels
				if (!connected) {

					// block till we have someone subscribing for data.
					this.connectSelector.select();

					selectedKeys = this.connectSelector.selectedKeys().iterator();
					// operate on keys set
					performKeyOperations(selectedKeys);

				} else if (linkUp) {
					// else we try I/O ops.
			
					if (this.readSelector.selectNow() > 0) {
						selectedKeys = this.readSelector.selectedKeys().iterator();
						// operate on keys set

						performKeyOperations(selectedKeys);

					}

					if (this.writeSelector.selectNow() > 0) {
						selectedKeys = this.writeSelector.selectedKeys().iterator();
						// operate on keys set

						performKeyOperations(selectedKeys);

					}

					if (hdlcHandler.isTxBufferEmpty()) {
						Thread.currentThread().sleep(4);
					}
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private void performKeyOperations(Iterator selectedKeys) throws IOException {

		while (selectedKeys.hasNext()) {

			SelectionKey key = (SelectionKey) selectedKeys.next();
			selectedKeys.remove();

			if (!key.isValid()) {
				// handle disconnect here?
				continue;
			}

			// Check what event is available and deal with it
			if (key.isAcceptable()) {

				this.accept(key);
			} else if (key.isReadable()) {

				this.read(key);
			} else if (key.isWritable()) {

				this.write(key);
			}
		}

	}

	public void send(byte sls, byte linksetId,byte[] data) {
		if (!connected) {
			if (logger.isInfoEnabled()) {
				logger.info("There is no client interested in data stream, ignoring. Message should be retransmited.");

			}
			return;
		}

		// And queue the data we want written
		//synchronized (this.txBuffer) {
		synchronized (this.hdlcHandler) {

			//this.txBuffer.add(ByteBuffer.wrap(data));
			ByteBuffer bb = ByteBuffer.allocate(2+data.length);
			bb.put(sls);
			bb.put(linksetId);
			bb.put(data);
			this.hdlcHandler.addToTxBuffer(bb);

		}

		// Finally, wake up our selecting thread so it can make the required
		// changes
		this.writeSelector.wakeup();
	}

	private void read(SelectionKey key) throws IOException {
		SocketChannel socketChannel = (SocketChannel) key.channel();

		// FIXME: we must ensure that we have whole frame here?
		// Clear out our read buffer so it's ready for new data
		this.readBuff.clear();

		// Attempt to read off the channel
		int numRead = -1;
		try {
			numRead = socketChannel.read(this.readBuff);
		} catch (IOException e) {
			// The remote forcibly closed the connection, cancel
			// the selection key and close the channel.
			handleClose(key);
			return;
		}

		if (numRead == -1) {
			// Remote entity shut the socket down cleanly. Do the
			// same from our end and cancel the channel.
			handleClose(key);
			return;
		}
		//pass it on.
		ByteBuffer[] readResult = null;

		this.readBuff.flip();
		while((readResult = this.hdlcHandler.processRx(this.readBuff))!=null)
		{
			for(ByteBuffer b:readResult)
			{
				byte sls = b.get();
				byte linksetId = b.get();
				this.layer3.send(sls,linksetId,si, ssf, b.array());
			}
		}
		this.readBuff.clear();
		//this.layer3.send(si, ssf, this.readBuff.array());

	}

	private void accept(SelectionKey key) throws IOException {

		ServerSocketChannel serverSocketChannel = (ServerSocketChannel) key.channel();
		if (connected) {
			serverSocketChannel.close();
			return;
		}

		channel = serverSocketChannel.accept();
		Socket socket = channel.socket();
		channel.configureBlocking(false);

		channel.register(this.readSelector, SelectionKey.OP_READ);
		channel.register(this.writeSelector, SelectionKey.OP_WRITE);

		connected = true;
		if (logger.isInfoEnabled()) {
			logger.info("Estabilished connection with: " + socket.getInetAddress() + ":" + socket.getPort());
			
		}
	}

	private void write(SelectionKey key) throws IOException {

		SocketChannel socketChannel = (SocketChannel) key.channel();

		// Write until there's not more data ?
		
		//while (!txBuffer.isEmpty()) {
		if(txBuff.remaining()>0)
		{
			socketChannel.write(txBuff);
			if(txBuff.remaining()>0)
			{
				//buffer filled.
				return;
			}else
			{
				
			}
		}
		//while (!this.hdlcHandler.isTxBufferEmpty()) {
		if (!this.hdlcHandler.isTxBufferEmpty()) {
			//ByteBuffer buf = (ByteBuffer) txBuffer.get(0);
			txBuff.clear();

			this.hdlcHandler.processTx(txBuff);
			txBuff.flip();
			
			socketChannel.write(txBuff);
			
			//if (buf.remaining() > 0) {
			if(txBuff.remaining()>0)
			{
				// ... or the socket's buffer fills up
				return;
			}
			//buf.clear();
			//txBuff.clear();
			//txBuffer.remove(0);
			

		}

	}

	
	private void handleClose(SelectionKey key) throws IOException {
		try {
			SocketChannel socketChannel = (SocketChannel) key.channel();
			key.cancel();
			socketChannel.close();

		} finally {
			connected = false;
			//synchronized (this.txBuffer) {
			synchronized (this.hdlcHandler) {
				// this is to ensure buffer does not have any bad data.
				//this.txBuffer.clear();
				this.hdlcHandler.clearTxBuffer();

			}
		}
		return;
	}

	// LAYER4
	public void linkDown() {
		if (logger.isInfoEnabled()) {
			logger.info("Received L4 Down event from layer3.");
		}
		this.linkUp = false;
	}

	public void linkUp() {
		if (logger.isInfoEnabled()) {
			logger.info("Received L4 Up event from layer3.");
		}
		this.linkUp = true;
	}

	public void receive(byte sls,byte linksetId,int service, int subservice, byte[] msgBuff) {
		// ONE CONNECTION, ONE PROTOCOL!!!!, so we can ignore service and
		// subservice

		// layer3 has something important, lets write.
		if(linkUp)
		{
			this.send(sls,linksetId,msgBuff);
		}
	}

	public String getAddress() {
		return this.address.toString();
	}

	public int getPort() {
		return this.port;
	}

	public void setAddress(String address) throws UnknownHostException {
		this.address = InetAddress.getAllByName(address)[0];

	}

	public void setPort(int port) {
		if (port > 0) {
			this.port = port;
		} else {
			// do nothing, use def
		}

	}

	public void start() throws Exception {
		this.initServer();
		this.runFuture = this.executor.submit(this);
	}

	public void stop() {
		if(this.runFuture == null)
			return;
		this.runFuture.cancel(false);
		this.runFuture = null;
	}

	private void initServer() throws Exception {
		// Create a new selector
		this.readSelector = SelectorProvider.provider().openSelector();
		this.writeSelector = SelectorProvider.provider().openSelector();
		this.connectSelector = SelectorProvider.provider().openSelector();
		// Create a new non-blocking server socket channel
		this.serverSocketChannel = ServerSocketChannel.open();
		serverSocketChannel.configureBlocking(false);

		// Bind the server socket to the specified address and port
		InetSocketAddress isa = new InetSocketAddress(this.address, this.port);
		serverSocketChannel.socket().bind(isa);

		// Register the server socket channel, indicating an interest in
		// accepting new connections
		serverSocketChannel.register(this.connectSelector, SelectionKey.OP_ACCEPT);
		logger.info("Initiaited server on: "+this.address+":"+this.port);
	}

	public void setLayer3(Mtp3 layer3) {
		this.layer3 = layer3;
		if (layer3 != null) {
			this.layer3.setLayer4(this);
		}

	}

	public void setServiceIndicator(int i) {
		this.si = i;

	}

	public void setSubServiceIndicator(int i) {
		this.ssf = i;

	}

}
