package org.mobicents.servlet.sip.testsuite.proxy;

import java.util.ArrayList;
import java.util.List;

import javax.sip.SipProvider;
import javax.sip.address.SipURI;
import javax.sip.message.Response;

import org.apache.log4j.Logger;
import org.mobicents.servlet.sip.SipServletTestCase;
import org.mobicents.servlet.sip.testsuite.ProtocolObjects;
import org.mobicents.servlet.sip.testsuite.TestSipListener;

public class ProxyRecordRoutePrackTest extends SipServletTestCase {
	private static transient Logger logger = Logger.getLogger(ProxyRecordRoutePrackTest.class);
	private static final boolean AUTODIALOG = true;
	TestSipListener sender;
	TestSipListener receiver;
	ProtocolObjects senderProtocolObjects;
	ProtocolObjects receiverProtocolObjects;

	private static final int TIMEOUT = 20000;

	public ProxyRecordRoutePrackTest(String name) {
		super(name);
	}

	@Override
	public void setUp() throws Exception {
		super.setUp();
	}

	// Receiver sends 180rel:INV and 200:INV immediately after it.
	// Sender sends PRACK and later ACK, proxy receives PRACK after already having
	// forwarded a 200:INV
	public void testProxySendPrackAfterFinalResponse() throws Exception {
		setupPhones("UDP");

		String fromName = "unique-location-prack";
		String fromSipAddress = "sip-servlets.com";
		SipURI fromAddress = senderProtocolObjects.addressFactory.createSipURI(fromName, fromSipAddress);

		String toSipAddress = "sip-servlets.com";
		String toUser = "proxy-receiver-prack";
		SipURI toAddress = senderProtocolObjects.addressFactory.createSipURI(toUser, toSipAddress);

		List<Integer> provisionalResponsesToSend = new ArrayList<Integer>();
		provisionalResponsesToSend.add(Response.SESSION_PROGRESS);
		provisionalResponsesToSend.add(Response.SESSION_PROGRESS);
		provisionalResponsesToSend.add(Response.RINGING);
		receiver.setProvisionalResponsesToSend(provisionalResponsesToSend);
		receiver.setTimeToWaitBetweenProvisionnalResponse(1000);

		receiver.setWaitForCancel(false);
		receiver.setWaitBeforeFinalResponse(650);
		receiver.setForceFinalResponseBeforePrack(true);
		receiver.setSendUpdateAfterUpdate(false);

		sender.setSendUpdateAfterPrack(false);
		sender.setSendUpdateAfterProvisionalResponses(false);
		sender.setSendUpdateOn180(false);
		sender.setDelayBeforePrack(50);
		sender.setTimeToWaitBeforeBye(2000);

		String[] headerNames = new String[] { "require" };
		String[] headerValues = new String[] { "100rel" };

		int TIMEOUT = 500;

		sender.sendSipRequest("INVITE", fromAddress, toAddress, null, null, false, headerNames, headerValues, true);

		Thread.sleep(1300);
		// first 183-prack-ok
		checkAndResetOnePrack();

		Thread.sleep(300);
		// second 183-prack-ok
		checkAndResetOnePrack();

		Thread.sleep(TIMEOUT * 4);

		assertTrue(sender.isAckSent());
		assertTrue(receiver.isAckReceived());

		assertTrue(receiver.isPrackReceived());
		assertTrue(sender.isOkToPrackReceived());

		sender.sendBye();
		Thread.sleep(TIMEOUT);
		assertTrue(receiver.getByeReceived());
		assertTrue(sender.getOkToByeReceived());
	}

	private void checkAndResetOnePrack() {
		// check
		assertTrue(sender.isPrackSent());
		assertTrue(receiver.isPrackReceived());
		assertTrue(sender.isOkToPrackReceived());
		// reset
		sender.setPrackSent(false);
		receiver.setPrackReceived(false);
		sender.setOkToPrackReceived(false);
	}

	public void setupPhones(String transport) throws Exception {
		senderProtocolObjects = new ProtocolObjects("proxy-sender", "gov.nist", transport, AUTODIALOG, null, null,
				null);
		receiverProtocolObjects = new ProtocolObjects("proxy-receiver", "gov.nist", transport, AUTODIALOG, null, "3",
				"true");
		sender = new TestSipListener(5080, 5070, senderProtocolObjects, false);
		sender.setRecordRoutingProxyTesting(true);

		SipProvider senderProvider = sender.createProvider();

		receiver = new TestSipListener(5057, 5070, receiverProtocolObjects, false);
		receiver.setRecordRoutingProxyTesting(true);
		SipProvider receiverProvider = receiver.createProvider();

		receiverProvider.addSipListener(receiver);
		senderProvider.addSipListener(sender);

		senderProtocolObjects.start();
		receiverProtocolObjects.start();
	}

	@Override
	public void tearDown() throws Exception {
		senderProtocolObjects.destroy();
		receiverProtocolObjects.destroy();
		logger.info("Test completed");
		super.tearDown();
	}

	@Override
	public void deployApplication() {
		assertTrue(tomcat.deployContext(
				projectHome + "/sip-servlets-test-suite/applications/proxy-sip-servlet/src/main/sipapp",
				"sip-test-context", "sip-test"));
	}

	@Override
	protected String getDarConfigurationFile() {
		return "file:///" + projectHome + "/sip-servlets-test-suite/testsuite/src/test/resources/"
				+ "org/mobicents/servlet/sip/testsuite/proxy/simple-sip-servlet-dar.properties";
	}
}
