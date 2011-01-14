/**
 * 
 */
package org.mobicents.protocols.ss7.isup.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.mobicents.protocols.ss7.isup.ISUPClientTransaction;
import org.mobicents.protocols.ss7.isup.ISUPListener;
import org.mobicents.protocols.ss7.isup.ISUPMessageFactory;
import org.mobicents.protocols.ss7.isup.ISUPParameterFactory;
import org.mobicents.protocols.ss7.isup.ISUPProvider;
import org.mobicents.protocols.ss7.isup.ISUPServerTransaction;
import org.mobicents.protocols.ss7.isup.ISUPTransaction;
import org.mobicents.protocols.ss7.isup.TransactionKey;
import org.mobicents.protocols.ss7.isup.impl.message.ISUPMessageImpl;
import org.mobicents.protocols.ss7.isup.impl.message.parameter.ISUPParameterFactoryImpl;

/**
 * @author baranowb
 * 
 */
public abstract class AbstractISUPProvider implements ISUPProvider {

	protected final List<ISUPListener> listeners = new ArrayList<ISUPListener>();
	protected ISUPStackImpl stack;
	protected ISUPMessageFactory messageFactory;
	protected ISUPParameterFactoryImpl parameterFactory;
	protected Map<TransactionKey, ISUPTransaction> transactionMap = new HashMap<TransactionKey, ISUPTransaction>();
	protected boolean linkUp = false;

	public AbstractISUPProvider(ISUPStackImpl isupStackImpl) {
		this.stack = isupStackImpl;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.isup.ISUPProvider#addListener(org.mobicents.isup.ISUPListener
	 * )
	 */
	public void addListener(ISUPListener listener) {
		listeners.add(listener);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @seeorg.mobicents.isup.ISUPProvider#removeListener(org.mobicents.isup.
	 * ISUPListener)
	 */
	public void removeListener(ISUPListener listener) {
		listeners.remove(listener);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.isup.ISUPProvider#getMessageFactory()
	 */
	public ISUPMessageFactory getMessageFactory() {
		return this.messageFactory;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.isup.ISUPProvider#getParameterFactory()
	 */
	public ISUPParameterFactory getParameterFactory() {
		return this.parameterFactory;
	}

	public void linkDown() {
		if (linkUp) {
			linkUp = false;
			for (ISUPListener l : this.listeners) {
				try {
					l.onTransportDown();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}

	public void linkUp() {
		if (!linkUp) {
			linkUp = true;
			for (ISUPListener l : this.listeners) {
				try {
					l.onTransportUp();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}

	}

	// FIXME: should we wait here to get all messages?
	void onTransactionTimeout(ISUPClientTransaction tx) {
		for (ISUPListener l : this.listeners) {
			try {
				l.onTransactionTimeout(tx);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		this.transactionMap.remove(((ISUPMessageImpl)tx.getOriginalMessage()).generateTransactionKey());

	}

	void onTransactionTimeout(ISUPServerTransaction tx) {
		for (ISUPListener l : this.listeners) {
			try {
				l.onTransactionTimeout(tx);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		this.transactionMap.remove(((ISUPMessageImpl)tx.getOriginalMessage()).generateTransactionKey());
	}

	void onTransactionEnded(ISUPClientTransaction tx) {
		for (ISUPListener l : this.listeners) {
			try {
				l.onTransactionEnded(tx);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		this.transactionMap.remove(((ISUPMessageImpl)tx.getOriginalMessage()).generateTransactionKey());
	}

	void onTransactionEnded(ISUPServerTransaction tx) {
		for (ISUPListener l : this.listeners) {
			try {
				l.onTransactionEnded(tx);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		this.transactionMap.remove(((ISUPMessageImpl)tx.getOriginalMessage()).generateTransactionKey());
	}

}
