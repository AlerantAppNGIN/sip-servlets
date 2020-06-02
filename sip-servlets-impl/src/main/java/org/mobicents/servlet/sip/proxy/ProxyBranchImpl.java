/*
 * TeleStax, Open Source Cloud Communications
 * Copyright 2011-2014, Telestax Inc and individual contributors
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

package org.mobicents.servlet.sip.proxy;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.sip.Proxy;
import javax.servlet.sip.ProxyBranch;
import javax.servlet.sip.ServletParseException;
import javax.servlet.sip.SipServletRequest;
import javax.servlet.sip.SipServletResponse;
import javax.servlet.sip.SipSession.State;
import javax.servlet.sip.SipURI;
import javax.servlet.sip.URI;
import javax.servlet.sip.ar.SipApplicationRoutingDirective;
import javax.sip.ClientTransaction;
import javax.sip.SipException;
import javax.sip.SipProvider;
import javax.sip.header.RouteHeader;
import javax.sip.header.ToHeader;
import javax.sip.header.ViaHeader;
import javax.sip.message.Request;
import javax.sip.message.Response;

import org.apache.log4j.Logger;
import org.mobicents.javax.servlet.sip.ProxyBranchListener;
import org.mobicents.javax.servlet.sip.ResponseType;
import org.mobicents.servlet.sip.JainSipUtils;
import org.mobicents.servlet.sip.SipConnector;
import org.mobicents.servlet.sip.address.AddressImpl.ModifiableRule;
import org.mobicents.servlet.sip.address.SipURIImpl;
import org.mobicents.servlet.sip.core.DispatcherException;
import org.mobicents.servlet.sip.core.MobicentsExtendedListeningPoint;
import org.mobicents.servlet.sip.core.RoutingState;
import org.mobicents.servlet.sip.core.SipApplicationDispatcher;
import org.mobicents.servlet.sip.core.SipNetworkInterfaceManager;
import org.mobicents.servlet.sip.core.dispatchers.MessageDispatcher;
import org.mobicents.servlet.sip.core.message.MobicentsSipServletRequest;
import org.mobicents.servlet.sip.core.message.MobicentsSipServletResponse;
import org.mobicents.servlet.sip.core.proxy.MobicentsProxyBranch;
import org.mobicents.servlet.sip.core.session.MobicentsSipApplicationSession;
import org.mobicents.servlet.sip.core.session.MobicentsSipSession;
import org.mobicents.servlet.sip.message.SipFactoryImpl;
import org.mobicents.servlet.sip.message.SipServletMessageImpl;
import org.mobicents.servlet.sip.message.SipServletRequestImpl;
import org.mobicents.servlet.sip.message.SipServletResponseImpl;
import org.mobicents.servlet.sip.message.TransactionApplicationData;
import org.mobicents.servlet.sip.rfc5626.IncorrectFlowIdentifierException;
import org.mobicents.servlet.sip.rfc5626.RFC5626Helper;
import org.mobicents.servlet.sip.startup.StaticServiceHolder;

import gov.nist.javax.sip.TransactionExt;
import gov.nist.javax.sip.header.Via;
import gov.nist.javax.sip.message.MessageExt;
import gov.nist.javax.sip.stack.SIPClientTransaction;

/**
 * @author jean.deruelle@telestax.com
 * @author vralev@gmail.com
 *
 */
public class ProxyBranchImpl implements MobicentsProxyBranch, Externalizable {

	private static final String DEFAULT_RECORD_ROUTE_URI = "sip:proxy@localhost";
	private static final long serialVersionUID = 1L;
	private static final Logger logger = Logger.getLogger(ProxyBranchImpl.class);
	private transient ProxyImpl proxy;
	private transient SipServletRequestImpl originalRequest;
	/** Reference to the original INVITE, only used for correct generation of CANCEL when cancel() is called on the proxy. */
	private transient SipServletRequestImpl originalBranchRequest;
	// From javadoc : object representing the request that is or to be proxied.
	private transient SipServletRequestImpl outgoingRequest;
	private transient SipServletResponseImpl lastResponse;
	// https://telestax.atlassian.net/browse/MSS-153 moving to String to optimize memory usage
	private String targetURI;
	// https://telestax.atlassian.net/browse/MSS-153 moving to String to optimize memory usage
	private transient String recordRouteURIString;
	// https://telestax.atlassian.net/browse/MSS-153 need to keep it as URI for the time of the transaction as
	// com.bea.sipservlet.tck.agents.spec.ProxyBranchTest.testAddNoSysHeader adds parameters to it that need to be passed on the outgoing invite
	private transient SipURI recordRouteURI;
	private boolean recordRoutingEnabled;
	// https://github.com/Mobicents/sip-servlets/issues/63
	private boolean appSpecifiedRecordRoutingEnabled = false;
	private boolean recurse;
	private transient SipURI pathURI;
	private boolean started;
	private boolean timedOut;
	private int proxyBranchTimeout;
	private int proxyBranch1xxTimeout;
	private transient ProxyBranchTimerTask proxyTimeoutTask;
	private transient ProxyBranchTimerTask proxy1xxTimeoutTask;
	private transient boolean proxyBranchTimerStarted;
	private transient boolean proxyBranch1xxTimerStarted;
	private transient Object cTimerLock;
	private boolean canceled;
	private boolean isAddToPath;
	private transient List<ProxyBranch> recursedBranches;
	private String fromTag;
	private String toTag;
	// https://telestax.atlassian.net/browse/MSS-153 not needing to store it
//	public transient ViaHeader viaHeader;
	
	/*
	 * It is best to use a linked list here because we expect more than one tx only very rarely.
	 * Hashmaps, sets, etc allocate some buffers, making them have much bigger mem footprint.
	 * This list is kept because we need to support concurrent INVITE and other transactions happening
	 * in both directions in proxy. http://code.google.com/p/mobicents/issues/detail?id=1852
	 * 
	 */
	public transient List<TransactionRequest> ongoingTransactions = new LinkedList<TransactionRequest>();
	
	public static class TransactionRequest {
		public TransactionRequest(String branch, SipServletRequestImpl request) {
			this.branchId = branch;
			this.request = request;
		}
		public String branchId;
		public SipServletRequestImpl request;
		
		@Override
		public String toString() {
			return "TR[b="+branchId+"; m="+request.getMethod() + "]";
		}
	}
	
	// empty constructor used only for Externalizable interface
	public ProxyBranchImpl() {}
	
	public ProxyBranchImpl(URI uri, ProxyImpl proxy)
	{
		this.targetURI = uri.toString();
		this.proxy = proxy;
		isAddToPath = proxy.getAddToPath();
		this.originalRequest = (SipServletRequestImpl) proxy.getOriginalRequest();
		this.fromTag = ((MessageExt)originalRequest.getMessage()).getFromHeader().getTag();
		this.toTag = null;
		this.originalBranchRequest = (SipServletRequestImpl) proxy.getOriginalRequest();
		if(proxy.recordRouteURI != null) {
		this.recordRouteURI = proxy.recordRouteURI;
		}
		if(proxy.recordRouteURIString != null) {
			this.recordRouteURIString = proxy.recordRouteURIString;
		}
		this.pathURI = proxy.pathURI;
//		if(recordRouteURI != null) {
//			this.recordRouteURI = (SipURI)((SipURIImpl)recordRouteURI).clone();			
//		}
		this.proxyBranchTimeout = proxy.getProxyTimeout();
		this.proxyBranch1xxTimeout = proxy.getProxy1xxTimeout();
		this.canceled = false;
		this.recursedBranches = null;
		proxyBranchTimerStarted = false;
		cTimerLock = new Object();
		
		// Here we create a clone which is available through getRequest(), the user can add
		// custom headers and push routes here. Later when we actually proxy the request we
		// will clone this request (with it's custome headers and routes), but we will override
		// the modified RR and Path parameters (as defined in the spec).
		Request cloned = (Request)originalRequest.getMessage().clone();
		((MessageExt)cloned).setApplicationData(null);
		this.outgoingRequest = (SipServletRequestImpl) proxy.getSipFactoryImpl().getMobicentsSipServletMessageFactory().createSipServletRequest(
				cloned,
				this.originalRequest.getSipSession(),
				null, null, false);
	}

	/* (non-Javadoc)
	 * @see javax.servlet.sip.ProxyBranch#cancel()
	 */
	public void cancel() {
		cancel(null, null);
	}

	/*
	 * (non-Javadoc)
	 * @see javax.servlet.sip.ProxyBranch#cancel(java.lang.String[], int[], java.lang.String[])
	 */
	public void cancel(String[] protocol, int[] reasonCode, String[] reasonText) {
		cancel(ProxyUtils.generateReasonHeaders(protocol, reasonCode, reasonText), null);
	}

	@Override
	public void cancel(List<String> reasonHeaders, MobicentsSipServletRequest originalCancelRequest) {
		if(logger.isDebugEnabled()) {
			logger.debug("cancel " + this);
		}

		if(proxy.getAckReceived()) throw new IllegalStateException("There has been an ACK received on this branch. Can not cancel.");
		
		try {			
			cancelTimer();
			// CANCEL can only be sent if the branch was started for an INVITE transaction
			if (this.isStarted() && !canceled && !timedOut && originalBranchRequest.getMethod().equalsIgnoreCase(Request.INVITE)) {
				SipServletRequestImpl inviteToCancel = originalBranchRequest.getLinkedRequest();
				SipServletResponse lastFinalResponse = inviteToCancel.getLastFinalResponse();
				if(lastFinalResponse != null) {
					if(!recursedBranches.isEmpty()) {
						//  Javadoc says it should throw an java.lang.IllegalStateException if the transaction has already been completed and it has no child branches
						if(logger.isDebugEnabled()) {
							logger.debug("lastFinalResponse status for the original INVITE is " + lastFinalResponse.getStatus() + " and branch has " + recursedBranches.size() + " recursed branches to cancel");
						}
					} else {
						logger.warn("Trying to cancel proxy branch with no recursed branches and final INVITE response: " + lastFinalResponse);
						canceled = true;
					}
					return;
				}

				/* According to SIP RFC we should send cancel only if we receive any response first*/
				if(inviteToCancel.hasReceivedAnyProvisionalResponse()) {
					SIPClientTransaction tx = (SIPClientTransaction) ((SipServletRequestImpl) inviteToCancel).getTransaction();
					if(logger.isDebugEnabled()) {
						logger.debug("Trying to cancel ProxyBranch for original outgoing INVITE request:\n"
								+ inviteToCancel
								+ "\n in transaction " + tx);
					}
					if (tx != null) {
						// even if in-dialog requests such as PRACK/INFO/UPDATE were sent during the early dialog, the CANCEL is always sent
						// for the original INVITE
						SipServletRequest cancelRequest = inviteToCancel.createCancel();

						//https://code.google.com/p/sipservlets/issues/detail?id=272 Adding reason headers if needed
						if (reasonHeaders != null) {
							for (String reasonHeaderValue : reasonHeaders) {
								((SipServletRequestImpl) cancelRequest).addHeaderInternal("Reason", reasonHeaderValue, false);
							}
						}

						if (originalCancelRequest != null && originalCancelRequest.getContentType() != null) {
							cancelRequest.setContent(originalCancelRequest.getRawContent(), originalCancelRequest.getContentType());
						}
						if (logger.isDebugEnabled()) {
							logger.debug("Trying to send downstream CANCEL request: " + cancelRequest);
						}
						cancelRequest.send();
					}
				} else {
					// We dont send cancel, but we must stop the invite retrans
					SIPClientTransaction tx = (SIPClientTransaction) originalBranchRequest.getLinkedRequest().getTransaction();
					if(tx != null) {
						if(logger.isDebugEnabled()) {
							logger.debug("No response received yet, simply disabling retransmission timer for transaction " + tx);
						}
						StaticServiceHolder.disableRetransmissionTimer.invoke(tx);
					} else {
						logger.warn("Transaction is null. Can not stop retransmission, they are already dead in the branch.");
					}

				}
				canceled = true;
				originalBranchRequest = null; // lose reference, it will not be used anymore
			}

			// a branch that was not started yet should always be canceled after a call to cancel()
			if(!this.isStarted()) {
				canceled = true;
			}
		}
		catch(Exception e) {
			throw new IllegalStateException("Failed canceling proxy branch", e);
		} finally {
			onBranchTerminated();
		}
		
	}


	// This will be called when we are sure this branch will not succeed and we moved on to other branches.
	public void onBranchTerminated() {
		if(outgoingRequest != null) {
			String txid = ((ViaHeader) outgoingRequest.getMessage().getHeader(ViaHeader.NAME)).getBranch();
			proxy.removeTransaction(txid);
		}
	}
	
	/* (non-Javadoc)
	 * @see javax.servlet.sip.ProxyBranch#getProxy()
	 */
	public Proxy getProxy() {
		return proxy;
	}

	/* (non-Javadoc)
	 * @see javax.servlet.sip.ProxyBranch#getProxyBranchTimeout()
	 */
	public int getProxyBranchTimeout() {
		return proxyBranchTimeout;
	}

	/* (non-Javadoc)
	 * @see javax.servlet.sip.ProxyBranch#getRecordRouteURI()
	 */
	public SipURI getRecordRouteURI() {
		if(this.getRecordRoute()) {
			if(this.recordRouteURI == null && this.recordRouteURIString == null) 
				this.recordRouteURIString = DEFAULT_RECORD_ROUTE_URI;

			if(recordRouteURIString != null) {
				try {
					recordRouteURI = ((SipURI)proxy.getSipFactoryImpl().createURI(recordRouteURIString));
					recordRouteURIString = null;
				} catch (ServletParseException e) {
					logger.error("A problem occured while setting the target URI while proxying a request " + recordRouteURI, e);
					return null;
				}
			}
			return recordRouteURI;
		}
		
		else throw new IllegalStateException("Record Route not enabled for this ProxyBranch. You must call proxyBranch.setRecordRoute(true) before getting an URI.");
	}

	/* (non-Javadoc)
	 * @see javax.servlet.sip.ProxyBranch#getRecursedProxyBranches()
	 */
	public List<ProxyBranch> getRecursedProxyBranches() {
		if(recursedBranches == null) {
			return new ArrayList<ProxyBranch>();
		}
		return recursedBranches;
	}
	
	public void addRecursedBranch(ProxyBranchImpl branch) {
		if(recursedBranches == null) {
			recursedBranches = new ArrayList<ProxyBranch>();
		}
		recursedBranches.add(branch);
	}
	
	/* (non-Javadoc)
	 * @see javax.servlet.sip.ProxyBranch#getRequest()
	 */
	public SipServletRequest getRequest() {
		return outgoingRequest;
	}

	/* (non-Javadoc)
	 * @see javax.servlet.sip.ProxyBranch#getResponse()
	 */
	public MobicentsSipServletResponse getResponse() {
		return lastResponse;
	}

	public void setResponse(MobicentsSipServletResponse response) {
		lastResponse = (SipServletResponseImpl) response;
		if (this.toTag == null && response.getStatus() != 100) {
			ToHeader responseToHeader = ((MessageExt)response.getMessage()).getToHeader();
			if (responseToHeader != null && responseToHeader.getTag() != null) {
				this.toTag = responseToHeader.getTag();
			}
		}
	}

	/* (non-Javadoc)
	 * @see javax.servlet.sip.ProxyBranch#isStarted()
	 */
	public boolean isStarted() {
		return started;
	}

	/* (non-Javadoc)
	 * @see javax.servlet.sip.ProxyBranch#setProxyBranchTimeout(int)
	 */
	public void setProxyBranchTimeout(int seconds) {
		if(seconds<=0) 
			throw new IllegalArgumentException("Negative or zero timeout not allowed");
		
		if(isCanceled() || isTimedOut()) {
			logger.error("Cancelled or timed out proxy branch should not be updated with new timeout values");
			return;
		}
		
		this.proxyBranchTimeout = seconds;
		if(this.started) updateTimer(false, originalRequest.getSipApplicationSession(false));
	}
	
	/**
	 * After the branch is initialized, this method proxies the initial request to the
	 * specified destination. Subsequent requests are proxied through proxySubsequentRequest
	 */
	public void start()	{
		if(started) {
			throw new IllegalStateException("Proxy branch alredy started!");
		}
		if(canceled) {
			throw new IllegalStateException("Proxy branch was cancelled, you must create a new branch!");
		}
		if(timedOut) {
			throw new IllegalStateException("Proxy brnach has timed out!");
		}
		if(proxy.getAckReceived()) {
			throw new IllegalStateException("An ACK request has been received on this proxy. Can not start new branches.");
		}
		
		// Initialize these here for efficiency.
		updateTimer(false, originalRequest.getSipApplicationSession(false));		
		
		SipURI recordRoute = null;
		
		// If the proxy is not adding record-route header, set it to null and it
		// will be ignored in the Proxying
		if(proxy.getRecordRoute() || this.getRecordRoute()) {
			if(recordRouteURI == null && recordRouteURIString == null) {
				recordRouteURIString = DEFAULT_RECORD_ROUTE_URI;
			}
			if(recordRouteURIString != null) {
				try {
					recordRouteURI = ((SipURI)proxy.getSipFactoryImpl().createURI(recordRouteURIString));
				} catch (ServletParseException e) {
					logger.error("A problem occured while setting the target URI while proxying a request " + recordRouteURIString, e);
				}
			}
			recordRoute = recordRouteURI;
		}
		addTransaction(originalRequest);
		
		URI destination = null;
                //app may have modified the branch request, so give it priority
                //fixes https://github.com/RestComm/sip-servlets/issues/131
                if (outgoingRequest.getRequestURI().equals(this.getProxy().getOriginalRequest().getRequestURI()))
                {
                    if(targetURI != null) {
                            try {
                                    destination = proxy.getSipFactoryImpl().createURI(targetURI);
                            } catch (ServletParseException e) {
                                    logger.error("A problem occured while setting the target URI while proxying a request " + targetURI, e);
                            }
                    }                    
                } else {
                    //the app has mofified the requestURI after branch creation..
                     destination = outgoingRequest.getRequestURI();
                }
		Request cloned = ProxyUtils.createProxiedRequest(
				outgoingRequest,
				this,
				destination,
				recordRoute, 
				this.pathURI);
		//tells the application dispatcher to stop routing the original request
		//since it has been proxied
		originalRequest.setRoutingState(RoutingState.PROXIED);
		
		if(logger.isDebugEnabled()) {
			logger.debug("Proxy Branch 1xx Timeout set to " + proxyBranch1xxTimeout);
		}
		if(proxyBranch1xxTimeout > 0) {
			proxy1xxTimeoutTask = new ProxyBranchTimerTask(this, ResponseType.INFORMATIONAL, originalRequest.getSipApplicationSession(false));				
			proxy.getProxyTimerService().schedule(proxy1xxTimeoutTask, proxyBranch1xxTimeout * 1000L);
			proxyBranch1xxTimerStarted = true;
		}
		
		started = true;
		forwardRequest(cloned, false);		
	}

    /**
	 * Forward the request to the specified destination. The method is used internally.
	 * @param request
	 * @param subsequent Set to false if the the method is initial
	 */
	private void forwardRequest(Request request, boolean subsequent) {

		if(logger.isDebugEnabled()) {
			logger.debug("creating cloned Request for proxybranch " + request);
		}
		final SipServletRequestImpl clonedRequest = (SipServletRequestImpl) proxy.getSipFactoryImpl().getMobicentsSipServletMessageFactory().createSipServletRequest(
				request,
				null,
				null, null, false);
		
		if(subsequent) {
			clonedRequest.setRoutingState(RoutingState.SUBSEQUENT);
		}
		
		this.outgoingRequest = clonedRequest;
		
		// Initialize the sip session for the new request if initial
		final MobicentsSipSession originalSipSession = originalRequest.getSipSession();
		clonedRequest.setCurrentApplicationName(originalRequest.getCurrentApplicationName());
		if(clonedRequest.getCurrentApplicationName() == null && subsequent) {
			clonedRequest.setCurrentApplicationName(originalSipSession.getSipApplicationSession().getApplicationName());
		}
		clonedRequest.setSipSession(originalSipSession);
		final MobicentsSipSession newSession = (MobicentsSipSession) clonedRequest.getSipSession();
		try {
			newSession.setHandler(originalSipSession.getHandler());
		} catch (ServletException e) {
			logger.error("could not set the session handler while forwarding the request", e);
			throw new RuntimeException("could not set the session handler while forwarding the request", e);
		}
		
		// Use the original dialog in the new session
		// commented out proxy applications shouldn't use any dialogs !!!
//		newSession.setSessionCreatingDialog(originalSipSession.getSessionCreatingDialog());
		
		// And set a reference to the proxy		
		newSession.setProxy(proxy);		
				
		try {
			RFC5626Helper.checkRequest(this, request, originalRequest);
		} catch (IncorrectFlowIdentifierException e1) {
			logger.warn(e1.getMessage());
			this.cancel();
			try {
				originalRequest.createResponse(403).send();
			} catch (IOException e) {
				logger.error("couldn't send 403 response", e1);
			}
			return;
		}
		//JSR 289 Section 15.1.6
		if(!subsequent) {
			// Subsequent requests can't have a routing directive?
			clonedRequest.setRoutingDirective(SipApplicationRoutingDirective.CONTINUE, originalRequest);
		}
		clonedRequest.getTransactionApplicationData().setProxyBranch(this);			
		try {
			clonedRequest.send();			
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
		proxy.putTransaction(clonedRequest);
	}	

	/**
	 * A callback. Here we receive all responses from the proxied requests we have sent.
	 * 
	 * @param response
	 * @throws DispatcherException 
	 */
	public void onResponse(final MobicentsSipServletResponse response, final int status) throws DispatcherException
	{
		// If we are canceled but still receiving provisional responses try to cancel them
		if(canceled && status < 200) {
			if(logger.isDebugEnabled()) {
				logger.debug("ProxyBranch " + this + " with outgoing request " + outgoingRequest + " cancelled and still receiving provisional response, trying to cancel them");
			}
			try {
				final SipServletRequest cancelRequest = outgoingRequest.createCancel();
				cancelRequest.send();
			} catch (Exception e) {
				if(logger.isDebugEnabled()) {
					logger.debug("Failed to cancel again a provisional response " + response.toString()
							, e);
				}
			}
		}

		// We have already sent TRYING, don't send another one
		if(status == 100) {
			if(logger.isDebugEnabled() && proxyBranch1xxTimerStarted) {
				logger.debug("1xx received, cancelling 1xx timer ");
			}
			cancel1xxTimer();
			return;
		}
		
		// Send informational responses back immediately
		if((status > 100 && status < 200) || (status >= 200 &&
				(Request.PRACK.equals(response.getMethod()) || Request.INFO.equals(response.getMethod()) 
						|| Request.UPDATE.equals(response.getMethod()) || Request.BYE.equals(response.getMethod()))))
		{
			// notify the application of provisional responses and early-dialog PRACK/INFO/UPDATE responses
			if(proxy.getSupervised()) {
				try {
					MessageDispatcher.callServlet(response);
				} catch (ServletException e) {
					throw new DispatcherException("Unexpected servlet exception while processing the response : " + response, e);
				} catch (IOException e) {
					throw new DispatcherException("Unexpected io exception while processing the response : " + response, e);
				} catch (Throwable e) {
					throw new DispatcherException("Unexpected exception while processing response : " + response, e);
				}
			}
			
			final SipServletResponseImpl proxiedResponse = 
				ProxyUtils.createProxiedResponse(response, this);
			
			if(proxiedResponse == null) {
				if(logger.isDebugEnabled())
					logger.debug("Response dropped because it was addressed to this machine.");
				return; // this response was addressed to this proxy
			}
			
			try {
				String branch = ((Via)proxiedResponse.getMessage().getHeader(Via.NAME)).getBranch();
				synchronized(this.ongoingTransactions) {
					for(TransactionRequest tr : this.ongoingTransactions) {
						if(tr.branchId.equals(branch)) {
							((SipServletResponseImpl)proxiedResponse).setTransaction(tr.request.getTransaction());
							((SipServletResponseImpl)proxiedResponse).setOriginalRequest(tr.request);
							break;
						}
					}
				}

				proxiedResponse.send();
				if(logger.isDebugEnabled())
					logger.debug("Proxy response sent out sucessfully");
			} catch (Exception e) {
				logger.error("A problem occured while proxying a response", e);
			}
			if(logger.isDebugEnabled())
				logger.debug("SipSession state " + response.getSipSession().getState());
			if(status == 200 &&
				(Request.PRACK.equals(response.getMethod()) || Request.UPDATE.equals(response.getMethod()))
				// Added for http://code.google.com/p/sipservlets/issues/detail?id=41
				&& State.EARLY.equals(response.getSipSession().getState())) {
				
				updateTimer(true, response.getSipApplicationSession(false));
			}
			
			// cleanup on final response for non-dialog-creating transactions: app will not be called again, so lose these fields
			if(status >= 200 && !JainSipUtils.DIALOG_CREATING_METHODS.contains(response.getMethod())) {
				if(logger.isDebugEnabled()) {
						logger.debug("Cleaning up ongoingTransactions, originalRequest, outgoingRequest, lastResponse and TAD after final response on non dialog creating " + response.getMethod());
				}
				for (Iterator<TransactionRequest> it = ongoingTransactions.iterator(); it.hasNext();) {
					if(it.next().request == originalRequest) { // actual instance checks, no equals needed
						it.remove();
						break;
					}
				}
				if (originalRequest == response.getSipSession().getSessionCreatingTransactionRequest()) {
					response.getSipSession().setSessionCreatingTransactionRequest(null);
				}
				originalRequest.cleanUp();
				originalRequest = null;
				outgoingRequest.cleanUp();
				outgoingRequest = null;
				lastResponse.cleanUp();
				lastResponse = null;
			}
			
			if(logger.isDebugEnabled())
					logger.debug("About to return from onResponse");
			
			return;
		}
		
		// Non-provisional responses must also cancel the timer, otherwise it will timeout
		// and return multiple responses for a single transaction.
		cancelTimer();
		
		if(status >= 600) // Cancel all 10.2.4
			this.proxy.cancelAllExcept(this, null, false, null);

		// Notify the application of branch responses before acting on redirection, e.g. to disable recursion to a disallowed URI
		// For final responses, ProxyImpl.sendFinalResponse will do the callback
		if(proxy.getSupervised() && response.isBranchResponse()) {
			try {
				MessageDispatcher.callServlet(response);
			} catch (ServletException e) {
				throw new DispatcherException("Unexpected servlet exception while processing the response : " + response, e);
			} catch (IOException e) {
				throw new DispatcherException("Unexpected io exception while processing the response : " + response, e);
			} catch (Throwable e) {
				throw new DispatcherException("Unexpected exception while processing response : " + response, e);
			}
		}

		// FYI: ACK is sent automatically by jsip when needed
		
		boolean recursed = false;
		if(status >= 300 && status < 400 && recurse) {
			String contact = response.getHeader("Contact");
			if(contact != null) {
				//javax.sip.address.SipURI uri = SipFactoryImpl.addressFactory.createAddress(contact);
				try {
					if(logger.isDebugEnabled())
						logger.debug("Processing recursed response");
					int start = contact.indexOf('<');
					int end = contact.indexOf('>');
					contact = contact.substring(start + 1, end);
					URI uri = proxy.getSipFactoryImpl().createURI(contact);
					ArrayList<SipURI> list = new ArrayList<SipURI>();
					list.add((SipURI)uri);
					List<ProxyBranch> pblist = proxy.createProxyBranches(list);
					ProxyBranchImpl pbi = (ProxyBranchImpl)pblist.get(0);
					this.addRecursedBranch(pbi);
					pbi.start();
					recursed = true;
				} catch (ServletParseException e) {
					throw new IllegalArgumentException("Can not parse contact header", e);
				}
			}
		}		
		if(status >= 200 && !recursed)
		{
			
			if(proxy.getFinalBranchForSubsequentRequests() == null ||
					(outgoingRequest != null && outgoingRequest.isInitial())) {
				if(logger.isDebugEnabled())
					logger.debug("Handling final response for initial request");
				this.proxy.onFinalResponse(this);
			} else {
				if(logger.isDebugEnabled())
					logger.debug("Handling final response for non-initial request");				
				this.proxy.sendFinalResponse(response, this);
			}
		}
		
	}

	/**
	 * Has the branch timed out?
	 * 
	 * @return
	 */
	public boolean isTimedOut() {
		return timedOut;
	}

	// https://code.google.com/p/sipservlets/issues/detail?id=238
	public void addTransaction(SipServletRequestImpl request) {
        if(!request.getMethod().equalsIgnoreCase("ACK") && !request.getMethod().equalsIgnoreCase("PRACK")) {
            String branch = ((Via)request.getMessage().getHeader(Via.NAME)).getBranch();
            this.ongoingTransactions.add(new TransactionRequest(branch, request));
            request.getTransactionApplicationData().setProxyBranch(this);
            if(logger.isDebugEnabled()) {
                logger.debug("Added " + request.getMethod() + " transaction " + branch + " to proxy branch.");
            }
        }
    }
	
	// https://code.google.com/p/sipservlets/issues/detail?id=238
	public void removeTransaction(String branch) {
		synchronized (this.ongoingTransactions) {
			final boolean removedFromOngoingTxs = this.ongoingTransactions.removeIf(tr -> tr.branchId.equals(branch));
			final boolean removedStoredMessages = removeStoredMessagesOfTransaction(branch);
			if (logger.isDebugEnabled()) {
				if (removedFromOngoingTxs || removedStoredMessages) {
					logger.debug("Removed transaction " + branch + " from proxy branch");
				} else {
					logger.debug("Removing transaction " + branch + " from proxy branch FAILED. Not found.");
				}
				logger.debug("ProxyBranch state:\n"
						+ " ### lastResponse:\n" + this.lastResponse
						+ " ### ongoingTransactions:\n" + this.ongoingTransactions + "\n"
						+ " ### originalRequest:\n" + this.originalRequest
						+ " ### originalBranchRequest:\n" + this.originalBranchRequest
						+ " ### outgoingRequest:\n" + this.outgoingRequest
						);
			}
		}
	}
	
	// remove all stored messages that match this branch
	private boolean removeStoredMessagesOfTransaction(final String branch) {
		boolean ret = false;
		if(matchesBranch(lastResponse, branch)) {
			lastResponse = null;
			ret = true;
			if (logger.isDebugEnabled()) {
				logger.debug("Removed lastResponse for branch " + branch + " from proxybranch");
			}
		}
		if(matchesBranch(originalRequest, branch)) {
			originalRequest = null;
			ret = true;
			if (logger.isDebugEnabled()) {
				logger.debug("Removed originalRequest for branch " + branch + " from proxybranch");
			}
		}
		if(matchesBranch(originalBranchRequest, branch)) {
			originalBranchRequest = null;
			ret = true;
			if (logger.isDebugEnabled()) {
				logger.debug("Removed originalBranchRequest for branch " + branch + " from proxybranch");
			}
		}
		if(matchesBranch(outgoingRequest, branch)) {
			outgoingRequest = null;
			ret = true;
			if (logger.isDebugEnabled()) {
				logger.debug("Removed outgoingRequest for branch " + branch + " from proxybranch");
			}
		}
		return ret;
	}
	
	private boolean matchesBranch(SipServletMessageImpl msg, String branch) {
		return branch.equals(Optional.ofNullable(msg).map(m -> m.getTransaction()).map(t -> t.getBranchId()).orElse(null));
	}
	
	/**
	 * Call this method when a subsequent request must be proxied through the branch.
	 * 
	 * @param request
	 */
	public void proxySubsequentRequest(MobicentsSipServletRequest sipServletRequest) {
		SipServletRequestImpl request = (SipServletRequestImpl) sipServletRequest;
		
		MobicentsSipServletResponse lastFinalResponse = (MobicentsSipServletResponse) request.getLastFinalResponse();
		if(lastFinalResponse != null && lastFinalResponse.isMessageSent()) {
		    // https://code.google.com/p/sipservlets/issues/detail?id=21
		    if(logger.isDebugEnabled()) {
		        logger.debug("Not proxying request as final response has already been sent for " + request);
		    }
		    return;
	    }
		
		addTransaction(request);
		// A re-INVITE needs special handling without going through the dialog-stateful methods
		if(request.getMethod().equalsIgnoreCase("INVITE")) {
			if(logger.isDebugEnabled()) {
				logger.debug("Proxying reinvite request " + request);
			}			
			proxyDialogStateless(request);
			return;
		}
		
		if(logger.isDebugEnabled()) {
			logger.debug("Proxying subsequent request " + request);
		}
		
		// Update the last proxied request
		request.setRoutingState(RoutingState.PROXIED);
		if(!request.getMethod().equalsIgnoreCase(Request.ACK) ) {
			proxy.setOriginalRequest(request);
			this.originalRequest = request;
		} else { // it is an ACK
			// After ACK, CANCEL cannot arrive anymore, so lose this ref that is only used in cancel(), which checks for proxy.getAckReceived()
			this.originalBranchRequest = null;
		}
		
		// No proxy params, sine the target is already in the Route headers
//		final ProxyParams params = new ProxyParams(null, null, null, null);
		Request clonedRequest = null;
		if(request.getMethod().equalsIgnoreCase(Request.NOTIFY) || request.getMethod().equalsIgnoreCase(Request.SUBSCRIBE)) {
			// https://github.com/RestComm/sip-servlets/issues/121 http://tools.ietf.org/html/rfc6665#section-4.3
			clonedRequest = ProxyUtils.createProxiedRequest(request, this, null, recordRouteURI, null);
		} else {
			clonedRequest = ProxyUtils.createProxiedRequest(request, this, null, null, null);
		}

//      There is no need for that, it makes application composition fail (The subsequent request is not dispatched to the next application since the route header is removed)
//		RouteHeader routeHeader = (RouteHeader) clonedRequest.getHeader(RouteHeader.NAME);
//		if(routeHeader != null) {
//			if(!((SipApplicationDispatcherImpl)proxy.getSipFactoryImpl().getSipApplicationDispatcher()).isRouteExternal(routeHeader)) {
//				clonedRequest.removeFirst(RouteHeader.NAME);	
//			}
//		}

		// https://telestax.atlassian.net/browse/MSS-153 perf optimization : we update the timer only on non ACK
		if(!clonedRequest.getMethod().equalsIgnoreCase(Request.ACK) ) { 
			updateTimer(false, request.getSipApplicationSession(false)); 
		}
 
		try {
			// Reset the proxy supervised state to default Chapter 6.2.1 - page down list bullet number 6
			proxy.setSupervised(true);
			if(clonedRequest.getMethod().equalsIgnoreCase(Request.ACK) ) { //|| clonedRequest.getMethod().equalsIgnoreCase(Request.PRACK)) {
				// we mark them as accessed so that HA replication can occur
				final MobicentsSipSession sipSession = request.getSipSession();
				final MobicentsSipApplicationSession sipApplicationSession = sipSession.getSipApplicationSession();
				sipSession.access();
				if(sipApplicationSession != null) {
					sipApplicationSession.access();
				}
				final String transport = JainSipUtils.findTransport(clonedRequest);
				SipFactoryImpl sipFactoryImpl = proxy.getSipFactoryImpl();
				SipNetworkInterfaceManager sipNetworkInterfaceManager = sipFactoryImpl.getSipNetworkInterfaceManager();
				final SipProvider sipProvider;
				final SipConnector sipConnector;
				MobicentsExtendedListeningPoint matchingListeningPoint = null;
				String outboundInterface = sipSession.getOutboundInterface();
				if (outboundInterface != null) {
					if (logger.isDebugEnabled()) {
						logger.debug(
								"Trying to find listening point with session outbound interface " + outboundInterface);
					}
					javax.sip.address.SipURI outboundInterfaceURI = null;
					try {
						outboundInterfaceURI = (javax.sip.address.SipURI) SipFactoryImpl.addressFactory
								.createURI(outboundInterface);
					} catch (ParseException e) {
						throw new IllegalArgumentException("couldn't parse the outbound interface " + outboundInterface,
								e);
					}
					matchingListeningPoint = sipNetworkInterfaceManager.findMatchingListeningPoint(outboundInterfaceURI,
							false);
					if (logger.isDebugEnabled()) {
						logger.debug("Matching listening point " + matchingListeningPoint);
					}
				}
				if (matchingListeningPoint != null) {
					sipProvider = matchingListeningPoint.getSipProvider();
					sipConnector = matchingListeningPoint.getSipConnector();
				} else {
					sipProvider = sipNetworkInterfaceManager.findMatchingListeningPoint(transport, false)
							.getSipProvider();
					sipConnector = StaticServiceHolder.sipStandardService.findSipConnector(transport);
				}
				// Optimizing the routing for AR (if any)
				if(sipConnector.isUseStaticAddress()) {
					JainSipUtils.optimizeRouteHeaderAddressForInternalRoutingrequest(
							sipConnector, clonedRequest, sipSession, sipFactoryImpl, transport);
					try {
						JainSipUtils.optimizeViaHeaderAddressForStaticAddress(sipConnector, clonedRequest, sipFactoryImpl, transport);
					} catch (Exception e) {
						throw new RuntimeException(e);
					}
				}
				try {
					RFC5626Helper.checkRequest(this, clonedRequest, originalRequest);
				} catch (IncorrectFlowIdentifierException e1) {
					logger.warn(e1.getMessage());		
					this.cancel();
					return;
				}
				sipProvider.sendRequest(clonedRequest);
				sipFactoryImpl.getSipApplicationDispatcher().updateRequestsStatistics(clonedRequest, false);
			}
			else {				
				forwardRequest(clonedRequest, true);
			}
			
		} catch (SipException e) {
			logger.error("A problem occured while proxying a subsequent request", e);
		}
	}
	
	/**
	 * This method proxies requests without updating JSIP dialog state. PRACK and re-INVITE
	 * requests require this kind of handling because:
	 * 1. PRACK occurs before a dialog has been established (and also produces OKs before
	 *  the final response)
	 * 2. re-INVITE when sent with the dialog method resets the internal JSIP CSeq counter
	 *  to 1 every time you need it, which causes issues like 
	 *  http://groups.google.com/group/mobicents-public/browse_thread/thread/1a22ccdc4c481f47
	 * 
	 * @param request
	 */
	public void proxyDialogStateless(SipServletRequestImpl request) {
		if(logger.isDebugEnabled()) {
			logger.debug("Proxying request dialog-statelessly " + request);
		}
		final SipFactoryImpl sipFactoryImpl = proxy.getSipFactoryImpl();
		final SipApplicationDispatcher sipApplicationDispatcher = sipFactoryImpl.getSipApplicationDispatcher();
		final MobicentsSipSession sipSession = request.getSipSession();
		final MobicentsSipApplicationSession sipAppSession = sipSession.getSipApplicationSession();
		// Update the last proxied request
		request.setRoutingState(RoutingState.PROXIED);
				
		URI targetURI = null; 
		String targetURIString = null; 
		if(request.getMethod().equals(Request.PRACK) || request.getMethod().equals(Request.ACK)) {
			targetURIString = this.targetURI;
		}
		
		// Determine the direction of the request. Either it's from the dialog initiator (the caller)
		// or from the callee
		if(!((MessageExt)request.getMessage()).getFromHeader().getTag().toString().equals(proxy.getCallerFromTag())) {
			// If it's from the callee we should send it in the other direction
			targetURIString = proxy.getPreviousNode();
		}
		if(targetURIString != null) {
			try {
				targetURI = sipFactoryImpl.createURI(targetURIString);
			} catch (ServletParseException e) {
				logger.error("A problem occured while setting the target URI while proxying a request " + targetURIString, e);
			}
		}
		SipURI recordRoute = null;
		if(recordRouteURI != null) {
			recordRoute = recordRouteURI;
		} else if (recordRouteURIString != null){
			try {
				recordRoute = ((SipURI)proxy.getSipFactoryImpl().createURI(recordRouteURIString));
			} catch (ServletParseException e) {
				logger.error("A problem occured while setting the target URI while proxying a request " + recordRouteURI, e);
			}
		}
		// https://code.google.com/p/sipservlets/issues/detail?id=274
		// as described in https://lists.cs.columbia.edu/pipermail/sip-implementors/2003-June/004986.html
		// we should record route on reINVITE as well for robustness in case of UA crash, so adding recordRouteURI in the call to this method
		Request clonedRequest = 
			ProxyUtils.createProxiedRequest(request, this, targetURI, recordRoute, null);

		ViaHeader viaHeader = (ViaHeader) clonedRequest.getHeader(ViaHeader.NAME);
		try {
			final String branch = JainSipUtils.createBranch(
					sipSession.getKey().getApplicationSessionId(),  
					sipApplicationDispatcher.getHashFromApplicationName(sipSession.getKey().getApplicationName()));			
			viaHeader.setBranch(branch);
		} catch (ParseException pe) {
			logger.error("A problem occured while setting the via branch while proxying a request", pe);
		}
		String transport = JainSipUtils.findTransport(clonedRequest);
		SipNetworkInterfaceManager sipNetworkInterfaceManager = sipFactoryImpl.getSipNetworkInterfaceManager();
		final SipProvider sipProvider;
		final SipConnector sipConnector;
		MobicentsExtendedListeningPoint matchingListeningPoint = null;
		String outboundInterface = sipSession.getOutboundInterface();
		if (outboundInterface != null) {
			if (logger.isDebugEnabled()) {
				logger.debug(
						"Trying to find listening point with session outbound interface " + outboundInterface);
			}
			javax.sip.address.SipURI outboundInterfaceURI = null;
			try {
				outboundInterfaceURI = (javax.sip.address.SipURI) SipFactoryImpl.addressFactory
						.createURI(outboundInterface);
			} catch (ParseException e) {
				throw new IllegalArgumentException("couldn't parse the outbound interface " + outboundInterface,
						e);
			}
			matchingListeningPoint = sipNetworkInterfaceManager.findMatchingListeningPoint(outboundInterfaceURI,
					false);
			if (logger.isDebugEnabled()) {
				logger.debug("Matching listening point " + matchingListeningPoint);
			}
		}
		if (matchingListeningPoint != null) {
			sipProvider = matchingListeningPoint.getSipProvider();
			sipConnector = matchingListeningPoint.getSipConnector();
		} else {
			sipProvider = sipNetworkInterfaceManager.findMatchingListeningPoint(transport, false)
					.getSipProvider();
			sipConnector = StaticServiceHolder.sipStandardService.findSipConnector(transport);
		}

		try {
			RFC5626Helper.checkRequest(this, clonedRequest, request);
		} catch (IncorrectFlowIdentifierException e1) {
			logger.warn(e1.getMessage());
			this.cancel();
			try {
				originalRequest.createResponse(403).send();
			} catch (IOException e) {
				logger.error("couldn't send 403 response", e1);
			}
			return;
		}
		
		if(logger.isDebugEnabled()) {
			logger.debug("Getting new Client Tx for request " + clonedRequest + "\n transport = " + transport);
		}
		// we mark them as accessed so that HA replication can occur		
		sipSession.access();
		if(sipAppSession != null) {
			sipAppSession.access();
		}


		ClientTransaction ctx = null;	
		try {	
			if(sipConnector != null && sipConnector.isUseStaticAddress()) {
				javax.sip.address.URI uri = clonedRequest.getRequestURI();
				RouteHeader route = (RouteHeader) clonedRequest.getHeader(RouteHeader.NAME);
				if(route != null) {
					uri = route.getAddress().getURI();
				}
				if(uri.isSipURI()) {
					javax.sip.address.SipURI sipUri = (javax.sip.address.SipURI) uri;
					String host = sipUri.getHost();
					int port = sipUri.getPort();
					if(sipFactoryImpl.getSipApplicationDispatcher().isExternal(host, port, transport)) {
						viaHeader.setHost(sipConnector.getStaticServerAddress());
						viaHeader.setPort(sipConnector.getStaticServerPort());
					}
				}
				JainSipUtils.optimizeRouteHeaderAddressForInternalRoutingrequest(sipConnector,
						clonedRequest, sipSession, sipFactoryImpl, transport);
			}
			ctx = sipProvider.getNewClientTransaction(clonedRequest);
			JainSipUtils.setTransactionTimers((TransactionExt) ctx, sipApplicationDispatcher);
			
			TransactionApplicationData appData = (TransactionApplicationData) request.getTransactionApplicationData();
			appData.setProxyBranch(this);
			ctx.setApplicationData(appData);
			
			final SipServletRequestImpl clonedSipServletRequest = (SipServletRequestImpl) proxy.getSipFactoryImpl().getMobicentsSipServletMessageFactory().createSipServletRequest(
					clonedRequest,
					sipSession,
					ctx, null, false);
			appData.setSipServletMessage(clonedSipServletRequest);
					 			
			clonedSipServletRequest.setRoutingState(RoutingState.SUBSEQUENT);
			// make sure to store the outgoing request to make sure the branchid for a ACK to a future reINVITE if this one is INFO
			// by example will have the correct branchid and not the one from the INFO
			this.outgoingRequest = clonedSipServletRequest;
			
			ctx.sendRequest();
			sipFactoryImpl.getSipApplicationDispatcher().updateRequestsStatistics(clonedRequest, false);
		} catch (Exception e) {
			logger.error("A problem occured while proxying a request " + request + " in a dialog-stateless transaction", e);
			JainSipUtils.terminateTransaction(ctx);
		} 
	}
	
	/**
	 * This callback is called when the remote side has been idle too long while
	 * establishing the dialog.
	 * @throws DispatcherException 
	 *
	 */
	public void onTimeout(ResponseType responseType) throws DispatcherException
	{
		if(!proxy.getAckReceived()) {
			this.cancel();
			if(responseType == ResponseType.FINAL) {
				cancel1xxTimer();
			}
			this.timedOut = true;
			if(originalRequest != null) {
			List<ProxyBranchListener> proxyBranchListeners = originalRequest.getSipSession().getSipApplicationSession().getSipContext().getListeners().getProxyBranchListeners();
			if(proxyBranchListeners != null) {
				for (ProxyBranchListener proxyBranchListener : proxyBranchListeners) {
					proxyBranchListener.onProxyBranchResponseTimeout(responseType, this);
				}
			}
			}
			// Just do a timeout response
			proxy.onBranchTimeOut(this);
			logger.warn("Proxy branch has timed out");
		} else {
			logger.debug("ACKed proxybranch has timeout");
		}
	}
	
	/**
	 * Restart the timer. Call this method when some activity shows the remote
	 * party is still online.
	 * @param mobicentsSipApplicationSession 
	 *
	 */
	public void updateTimer(boolean cancel1xxTimer, MobicentsSipApplicationSession mobicentsSipApplicationSession) {
		if(cancel1xxTimer) {
			cancel1xxTimer();
		}
		cancelTimer();		
		if(proxyBranchTimeout > 0) {			
			synchronized (cTimerLock) {
				if(!proxyBranchTimerStarted) {
					try {
						final ProxyBranchTimerTask timerCTask = new ProxyBranchTimerTask(this, ResponseType.FINAL, mobicentsSipApplicationSession);
						if(logger.isDebugEnabled()) {
							logger.debug("Proxy Branch Timeout set to " + proxyBranchTimeout);
						}
						proxy.getProxyTimerService().schedule(timerCTask, proxyBranchTimeout * 1000L);
						proxyTimeoutTask = timerCTask;
						proxyBranchTimerStarted = true;
					} catch (IllegalStateException e) {
						logger.error("Unexpected exception while scheduling Timer C" ,e);
					}	
				}
			}
		}		
	}
	
	/**
	 * Stop the C Timer.
	 */
	public void cancelTimer() {
		synchronized (cTimerLock) {
			if (proxyTimeoutTask != null && proxyBranchTimerStarted) {
				proxyTimeoutTask.cancel();
				proxyTimeoutTask = null;
				proxyBranchTimerStarted = false;
			}
		}
	}

	/**
	 * Stop the Extension Timer for 1xx.
	 */
	public void cancel1xxTimer() {
		if (proxy1xxTimeoutTask != null && proxyBranch1xxTimerStarted) {
			proxy1xxTimeoutTask.cancel();
			proxy1xxTimeoutTask = null;
			proxyBranch1xxTimerStarted = false;
		}
	}

	public boolean isCanceled() {
		return canceled;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean getAddToPath() {
		return isAddToPath;
	}

	/**
	 * {@inheritDoc}
	 */
	public SipURI getPathURI() {
		if(!isAddToPath) {
			throw new IllegalStateException("addToPath is not enabled!");
		}
		return this.pathURI;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean getRecordRoute() {
		return recordRoutingEnabled;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean getRecurse() {
		return recurse;
	}

	/**
	 * {@inheritDoc}
	 */
	public void setAddToPath(boolean isAddToPath) {
		if(started) {
			throw new IllegalStateException("Cannot set a record route on an already started proxy");
		}
		if(this.pathURI == null) {
			this.pathURI = new SipURIImpl (JainSipUtils.createRecordRouteURI( proxy.getSipFactoryImpl().getSipNetworkInterfaceManager(), null), ModifiableRule.NotModifiable);
		}		
		this.isAddToPath = isAddToPath;
	}
	
	public boolean isAddToPath() {
		return this.isAddToPath;
	}

	/**
	 * {@inheritDoc}
	 */
	public void setOutboundInterface(InetAddress inetAddress) {
		// Since the value set here was never actually used anywhere, don't even bother saving the value or performing any checks...
		// Note that the spec is broken by not throwing an exception for invalid values, but we'd rather save some cpu cycles here.
		if(logger.isDebugEnabled()) {
			logger.debug("Ignoring setOutboundInterface " + inetAddress);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void setOutboundInterface(InetSocketAddress inetSocketAddress) {
		// Since the value set here was never actually used anywhere, don't even bother saving the value or performing any checks...
		// Note that the spec is broken by not throwing an exception for invalid values, but we'd rather save some cpu cycles here.
		if(logger.isDebugEnabled()) {
			logger.debug("Ignoring setOutboundInterface " + inetSocketAddress);
		}
	}
	
	/*
	 * (non-Javadoc)
	 * @see org.mobicents.javax.servlet.sip.ProxyExt#setOutboundInterface(javax.servlet.sip.SipURI)
	 */
	public void setOutboundInterface(SipURI outboundInterface) {
		// Since the value set here was never actually used anywhere, don't even bother saving the value or performing any checks...
		// Note that the spec is broken by not throwing an exception for invalid values, but we'd rather save some cpu cycles here.
		if(logger.isDebugEnabled()) {
			logger.debug("Ignoring setOutboundInterface " + outboundInterface);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void setRecordRoute(boolean isRecordRoute) {
		if(started) {
			throw new IllegalStateException("Proxy branch alredy started!");
		}
		recordRoutingEnabled = isRecordRoute;
	}

	/**
	 * {@inheritDoc}
	 */
	public void setRecurse(boolean isRecurse) {
		recurse = isRecurse;
	}

	/**
	 * @param proxy the proxy to set
	 */
	public void setProxy(ProxyImpl proxy) {
		this.proxy = proxy;
	}

	public void readExternal(ObjectInput in) throws IOException,
			ClassNotFoundException {
		cTimerLock = new Object();
		recurse = in.readBoolean();
		recordRoutingEnabled = in.readBoolean();
		started = in.readBoolean();
		timedOut = in.readBoolean();
		proxyBranchTimeout = in.readInt();
		proxyBranch1xxTimeout = in.readInt();
		canceled = in.readBoolean();
		isAddToPath = in.readBoolean();
		appSpecifiedRecordRoutingEnabled = in.readBoolean();
	}

	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeBoolean(recurse);
		out.writeBoolean(recordRoutingEnabled);
		out.writeBoolean(started);
		out.writeBoolean(timedOut);
		out.writeInt(proxyBranchTimeout);
		out.writeInt(proxyBranch1xxTimeout);
		out.writeBoolean(canceled);
		out.writeBoolean(isAddToPath);
		out.writeBoolean(appSpecifiedRecordRoutingEnabled);
	}
	
	/*
	 * (non-Javadoc)
	 * @see org.mobicents.javax.servlet.sip.ProxyBranchExt#getProxyBranch1xxTimeout()
	 */
	public int getProxyBranch1xxTimeout() {
		return proxyBranch1xxTimeout;
	}

	/*
	 * (non-Javadoc)
	 * @see org.mobicents.javax.servlet.sip.ProxyBranchExt#setProxyBranch1xxTimeout(int)
	 */
	public void setProxyBranch1xxTimeout(int timeout) {
		proxyBranch1xxTimeout= timeout;
		
	}

	/**
	 * @param outgoingRequest the outgoingRequest to set
	 */
	public void setOutgoingRequest(SipServletRequestImpl outgoingRequest) {
		this.outgoingRequest = outgoingRequest;
	}

	/**
	 * @param originalRequest the originalRequest to set
	 */
	public void setOriginalRequest(SipServletRequestImpl originalRequest) {
		this.originalRequest = originalRequest;
		if(originalRequest == null && recordRouteURI != null) {
			recordRouteURIString = recordRouteURI.toString().intern();
			recordRouteURI = null;
		}
	}

	/**
	 * @return the originalRequest
	 */
	public SipServletRequestImpl getOriginalRequest() {
		return originalRequest;
	}

	/**
	 * @param targetURI the targetURI to set
	 */
	public void setTargetURI(String targetURI) {
		this.targetURI = targetURI;
	}

	/**
	 * @return the targetURI
	 */
	public String getTargetURI() {
		return targetURI;
	}

	@Override
	public void setRecordRouteURI(SipURI uri) {
		this.recordRouteURI = uri;
		this.recordRouteURIString = null;
	}

	/**
	 * @return the userSpecifiedRecordRoutingEnabled
	 */
	public boolean isAppSpecifiedRecordRoutingEnabled() {
		return appSpecifiedRecordRoutingEnabled;
	}

	public String getFromTag() {
		return fromTag;
	}

	public String getToTag() {
		return toTag;
	}

}
