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

package org.mobicents.protocols.ss7.isup.impl;

import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.mobicents.protocols.ss7.isup.ISUPProvider;
import org.mobicents.protocols.ss7.isup.ISUPServerTransaction;
import org.mobicents.protocols.ss7.isup.ISUPTransaction;
import org.mobicents.protocols.ss7.isup.TransactionKey;
import org.mobicents.protocols.ss7.isup.impl.message.ISUPMessageImpl;
import org.mobicents.protocols.ss7.isup.message.ISUPMessage;
import org.mobicents.protocols.ss7.mtp.RoutingLabel;

/**
 * Start time:12:57:29 2009-09-04<br>
 * Project: mobicents-isup-stack<br>
 * 
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public abstract class ISUPTransactionImpl implements ISUPTransaction {

	private static final AtomicLong txID = new AtomicLong(0);
	protected TransactionKey transactionKey = null;

	protected ISUPMessage message;

	protected AbstractISUPProvider provider;
	protected ISUPStackImpl stack;

	protected Future generalTimeoutFuture;

	public ISUPTransactionImpl(ISUPMessage message, AbstractISUPProvider provider, ISUPStackImpl stack) {
		super();
		if (message == null) {
			throw new NullPointerException("Message can not be null!");
		}

		if (provider == null) {
			throw new NullPointerException("Provider can not be null!");
		}

		if (stack == null) {
			throw new NullPointerException("Stack can not be null!");
		}

		this.message = message;
		this.provider = provider;
		this.stack = stack;
		this.transactionKey = ((ISUPMessageImpl)this.message).generateTransactionKey();
		startGeneralTimer();

	}

	public ISUPProvider getProvider() {
		return provider;
	}

	public void setProvider(ISUPMtpProviderImpl provider) {
		this.provider = provider;
	}

	public ISUPStackImpl getStack() {
		return stack;
	}

	public void setStack(ISUPStackImpl stack) {
		this.stack = stack;
	}

	public void setMessage(ISUPMessage message) {
		this.message = message;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.isup.ISUPTransaction#getMessage()
	 */
	public ISUPMessage getOriginalMessage() {
		return this.message;
	}

	public TransactionKey getTransactionKey() {
		return this.transactionKey;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.isup.ISUPTransaction#isServerTransaction()
	 */
	public boolean isServerTransaction() {
		return this instanceof ISUPServerTransaction;
	}

	protected void cancelGeneralTimer() {

		if (this.generalTimeoutFuture != null) {
			this.generalTimeoutFuture.cancel(false);
			this.generalTimeoutFuture = null;
		}
	}

	protected void startGeneralTimer() {
		this.generalTimeoutFuture = stack.getExecutors().schedule(new ISUPTransactionTimeoutTask(this),
				stack.getTransactionGeneralTimeout(), TimeUnit.MILLISECONDS);

	}

	protected abstract void doGeneralTimeout();

	private class ISUPTransactionTimeoutTask implements Runnable {
		private ISUPTransactionImpl transaction;

		public ISUPTransactionTimeoutTask(ISUPTransactionImpl transaction) {
			super();
			this.transaction = transaction;
		}

		public void run() {

			transaction.doGeneralTimeout();
		}

	}

}
