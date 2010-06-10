/*
 * Mobicents, Communications Middleware
 * 
 * Copyright (c) 2008, Red Hat Middleware LLC or third-party
 * contributors as
 * indicated by the @author tags or express copyright attribution
 * statements applied by the authors.  All third-party contributions are
 * distributed under license by Red Hat Middleware LLC.
 *
 * This copyrighted material is made available to anyone wishing to use, modify,
 * copy, or redistribute it subject to the terms and conditions of the GNU
 * Lesser General Public License, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this distribution; if not, write to:
 * Free Software Foundation, Inc.
 * 51 Franklin Street, Fifth Floor
 *
 * Boston, MA  02110-1301  USA
 */
package org.mobicents.protocols.ss7.mtp;

import java.io.IOException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.mobicents.protocols.ss7.mtp.Mtp3.Test;

/**
 * 
 * @author kulikov
 * @author baranowb
 */
public class Mtp2 {

    final static int MTP2_OUT_OF_SERVICE = 0;
    /**
     * Initial state of IAC phase, we send "O" here. "E","O","N" have never been
     * received.
     */
    final static int MTP2_NOT_ALIGNED = 1;
    /**
     * Second state of IAC, we received one of: E,O,N. Depending on state we
     * send E or N.
     */
    final static int MTP2_ALIGNED = 2;
    /**
     * Third state, entered from ALIGNED on receival of N or E
     */
    final static int MTP2_PROVING = 3;
    /**
     * Etnered on certain condition when T4 fires.
     */
    final static int MTP2_ALIGNED_READY = 4;
    /**
     * In service state, entered from ALIGNED_READY on FISU/MSU
     */
    final static int MTP2_INSERVICE = 5;
    
    /**
     * Timers
     */
    private final static int T2_TIMEOUT = 5000;
    private final static int T3_TIMEOUT = 2000;
    private final static int T4_TIMEOUT_NORMAL = 9500;
    private final static int T4_TIMEOUT_EMERGENCY = 500;
    
    // not a static, since it can change.
    private int T4_TIMEOUT = T4_TIMEOUT_NORMAL;
    private int T7_TIMEOUT = 2000;
    
    // see Q704 - after alignemtn failure we need to wait before we retry
    // 800-1500.
    private final static int T17_TIMEOUT = 1500;
    
    private final static int fcstab[] = new int[]{0x0000, 0x1189, 0x2312,
        0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1, 0xaf5a,
        0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7, 0x1081, 0x0108, 0x3393,
        0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e, 0x9cc9, 0x8d40, 0xbfdb,
        0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876, 0x2102, 0x308b, 0x0210,
        0x1399, 0x6726, 0x76af, 0x4434, 0x55bd, 0xad4a, 0xbcc3, 0x8e58,
        0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5, 0x3183, 0x200a, 0x1291,
        0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9,
        0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974, 0x4204, 0x538d, 0x6116,
        0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb, 0xce4c, 0xdfc5, 0xed5e,
        0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3, 0x5285, 0x430c, 0x7197,
        0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a, 0xdecd, 0xcf44, 0xfddf,
        0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72, 0x6306, 0x728f, 0x4014,
        0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c,
        0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1, 0x7387, 0x620e, 0x5095,
        0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738, 0xffcf, 0xee46, 0xdcdd,
        0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70, 0x8408, 0x9581, 0xa71a,
        0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x0840, 0x19c9, 0x2b52,
        0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff, 0x9489, 0x8500, 0xb79b,
        0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036, 0x18c1, 0x0948, 0x3bd3,
        0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e, 0xa50a, 0xb483, 0x8618,
        0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5, 0x2942, 0x38cb, 0x0a50,
        0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd, 0xb58b, 0xa402, 0x9699,
        0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1,
        0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c, 0xc60c, 0xd785, 0xe51e,
        0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3, 0x4a44, 0x5bcd, 0x6956,
        0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb, 0xd68d, 0xc704, 0xf59f,
        0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232, 0x5ac5, 0x4b4c, 0x79d7,
        0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a, 0xe70e, 0xf687, 0xc41c,
        0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1, 0x6b46, 0x7acf, 0x4854,
        0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9, 0xf78f, 0xe606, 0xd49d,
        0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e, 0x58d5,
        0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
    };    
    // this is buff size, in native, but we use actaull data
    public final static int RX_TX_BUFF_SIZE = 16;    
    // status indicator of out of alignment (SIO). This condition occurs when a
    // signal unit is received that has a
    // ones-density violation (the data field simulated a flag) or the SIF has
    // exceeded its maximum capacity of 272
    // octets. The SIO is sent when a link has failed and the alignment
    // procedure is initiated.
    private final static int FRAME_STATUS_INDICATION_O = 0;    
    // Link status indicator of normal (SIN) or emergency (SIE) indicates that
    // the transmitting signaling point has
    // initiated the alignment procedure. The link is made unavailable for MSUs,
    // and only FISUs are transmitted to the
    // affected signaling point until a proving period has been passed. After
    // successful completion of a proving period,
    // MSUs can be transmitted over the link to the affected signaling point.
    private final static int FRAME_STATUS_INDICATION_N = 1;
    private final static int FRAME_STATUS_INDICATION_E = 2;    
    // An LSSU status indicator of out of service (SIOS) indicates that the
    // sending signaling point cannot receive or
    // transmit any MSUs for reasons other than a processor outage. On receipt
    // of an SIOS, the receiving signaling point
    // stops the transmission of MSUs and begins transmitting FISUs. The SIOS is
    // also sent at the beginning of the
    // alignment procedure.
    private final static int FRAME_STATUS_INDICATION_OS = 3;    
    // status indicator of processor outage (SIPO) indicates that the
    // transmitting signaling point cannot communicate
    // with levels 3 and 4.
    private final static int FRAME_STATUS_INDICATION_PO = 4;
    private final static int FRAME_STATUS_INDICATION_B = 5;
    private final static int FRAME_FISU = 6;
    
    private final static String[] FRAME_NAMES;
    

    static {
        FRAME_NAMES = new String[]{"SIO", "SIN", "SIE", "SIOS", "SIPO",
                    "SIPB", "FISU"
                };

    }
    
    public final static int AERM_THRESHOLD_NORMAL = 4;
    public final static int AERM_THRESHOLD_EMERGENCY = 1;    
    
    // /////////////////////////////////////////////
    // States for MTP2, for now we merge IAC,LSC //
    // /////////////////////////////////////////////
    // Some static vals used for debug.
    private final static String[] STATE_NAMES;
    

    static {
        STATE_NAMES = new String[]{"OUT_OF_SERVICE", "NOT_ALIGNED",
                    "ALIGNED", "PROVING", "ALIGNED_READY", "IN_SERVICE"
                };

    }    
    
    // ///////////////////
    // MTP2 stuff only //
    // ///////////////////

    // be careful using this, we do not sync for now.
    private int state;
    
    //MTP1 layer reference.
    private Mtp1 channel;    
    //MTP3 Layer reference
    private Mtp3 mtp3;
    
    private volatile boolean started;
    
    //HDLC components
    private FastHDLC hdlc = new FastHDLC();
    private HdlcState rxState = new HdlcState();
    private HdlcState txState = new HdlcState();
    
    private int rxLen = 0;
    private int txLen = 0;
    private int txOffset = 0;
    private byte[] txBuffer = new byte[RX_TX_BUFF_SIZE];
    private byte[] rxBuffer = new byte[RX_TX_BUFF_SIZE];

    private int[] rxFrame = new int[279];
    private byte[] txFrame = new byte[279];
    /**
     * Last write timestamp, it is required for case when we must start sending but nothing comes on wire.
     */
    private long lastWriteStamp = 0;    
    // Used only for LSSU, in some case we need to schedule LSSU frame, before
    // last is processed,
    private TxQueue txQueue = new TxQueue();
    private int doCRC = 0;
    private int rxCRC = 0xffff;
    private int txCRC = 0xffff;    
    
    // //////////////////////
    // SEQUENCING AND RTR //
    // //////////////////////
    /**
     * Holds byte[] sent on link, indexed by FSN, this is the place to get data
     * from when we send and retransmission is requested. FIXME: add this->
     * ACKED buffers will have len == 0(isFree() == true);
     */
    private Mtp2SendBuffer[] transmissionBuffer = new Mtp2SendBuffer[128];
    private static final int _OFF_RTR = -1;
    /**
     * Determines posistion in transmissionBuffer. If != _OFF_RTR, it points
     * next frame to be put into retransmission. Retransmission will occur until
     * ticks wont get to point where buffer.isFree() == true. It also point to
     * next MSU if scheduledby MTP3. This number is set as FSN.
     */
    private int retransmissionFSN = _OFF_RTR;
    /**
     * This is last ACKED FSN(meaning this is BSN received in SU comming from
     * other peer.
     */
    private int retransmissionFSN_LastAcked = 0;
    /**
     * This is FSN we used as last for send SU. If we spin many times and it
     * equals retransmissionFSN_LastAcked, it means we have queue full, and have
     * to discard SU
     */
    private int retransmissionFSN_LastSent = 0;
    private int sendFIB;
    private int sendBSN;
    private int sendBIB;
    /**
     * if bsnErrors > 2, link fails. See Q.703 section 5.3.[1,2]
     */
    private int bsnErrors = 0;
    protected String name;    

    // AERM variables. we use eCounter for AERM errors
    private static final int PROVING_ATTEMPTS_THRESHOLD = 5;
    
    private int aermThreshold;
    private boolean aermEnabled;
    private boolean emergency = false;
    private int provingAttempts;
    private boolean futureProving;
    private int nCount;
    private int dCount;
    private int eCount;
    /**
     * SLS, range is 0-15
     */
    protected int sls = -1;
    /**
     * Subservice field of mtp msg. See Q.704.14.2.2
     */
    private int subservice = -1;
    /**
     * SLTM tries for this link, values that are ok {0,1}, if over 1, its SLTM
     * restart
     */
    private AtomicInteger sltmTries = new AtomicInteger(0);

    protected Test test;
    private static final Logger logger = Logger.getLogger(Mtp2.class);
    
    public Mtp2(Mtp3 mtp3, Mtp1 channel, int sls) {    
	this(mtp3.name + ":" + channel, sls, Utils._VALUE_NOT_SET);
        this.channel = channel;        
        this.mtp3 = mtp3;
        channel.setLink(this);
    }
    
    public Mtp2(String name) {
        this(name, Utils._VALUE_NOT_SET, Utils._VALUE_NOT_SET);
    }

    public Mtp2(String name, int sls) {
        this(name, sls, Utils._VALUE_NOT_SET);
    }

    public Mtp2(String name, int sls, int subservice) {
        this.name = name;
        this.sls = sls;
        this.subservice = subservice;
        // init HDLC
        hdlc.fasthdlc_precalc();
        hdlc.fasthdlc_init(rxState);
        hdlc.fasthdlc_init(txState);

        // init error rate monitor
        aermThreshold = AERM_THRESHOLD_NORMAL;

        // init buffer
        for (int i = 0; i < this.transmissionBuffer.length; i++) {
            this.transmissionBuffer[i] = new Mtp2SendBuffer();
        }
    }

    public boolean isEmergency() {
        return emergency;
    }

    public void setEmergency(boolean emergency) {
        this.emergency = emergency;
    }

    public void restartSltmTries() {
        this.sltmTries.set(0);
    }

    public int incrementSltmTries() {
        return this.sltmTries.incrementAndGet();
    }

    public int getSltmTries() {
        return this.sltmTries.get();
    }

    public int getState() {

        return this.state;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.media.server.impl.resource.ss7.factories.Mtp2#getSubService
     * ()
     */
    public int getSubService() {

        return this.subservice;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.mobicents.media.server.impl.resource.ss7.factories.Mtp2#setSubService()
     */
    public void setSubService(int subservice) {
        this.subservice = subservice;
    }

    /**
     * Assigns layer 1 implementation.
     * 
     * @param layer1
     *            the implementation of MTP1 layer.
     */
    public void setLayer1(Mtp1 layer1) {
        this.channel = layer1;
    }

    public Mtp1 getChannel() {
	return channel;
    }
    
    public void setLayer3(Mtp3 layer3) {
        this.mtp3 = layer3;
//        this.listeners.add(layer3);
    }

    public void startLink() throws IOException {
        if (channel == null) {
            throw new IllegalStateException("Layer1 is not set in Layer2!");
        }
        
        if (started) {
            throw new IllegalStateException("Link already running");
        }
        
        channel.open();
        mtp3.selector.register(this);
        started = true;

        this.reset();

        if (this.enabledL2Debug) {
            trace("Is out fo service now");
        }
        // perform initial read, to make buffer empty.
        //this.layer1.read(rxBuffer);
        // mimics power on.

        // queueLSSU(Mtp2.FRAME_STATUS_INDICATION_OS);

        // poll = mtpThread.submit(this);
        // t = this.threadFactory.newThread(this);
        // t.start();
        state = Mtp2.MTP2_OUT_OF_SERVICE;
        
        //send Out of service indicator when link starts.
        queueLSSU(Mtp2.FRAME_STATUS_INDICATION_OS);
        processTx(16);
	startInitialAlignment();
    }

    public void stopLink() {
        started = false;
        // poll.cancel(false);
        // stop_T2();
        // stop_T3();
        // stop_T4();
        // stop_T17();
        reset();
        this.channel.close();

    // layer1.close();
    }

    public void _closeLink() {
        stopLink();
        //layer1.close();
        channel = null;
    }

    // not used
    private void startInitialAlignment() {
        startInitialAlignment(true);
    }

    // should not be used
    protected void startInitialAlignment(boolean resetTxOffset) {
	logger.info(String.format("(%s) Starting initial alignment", name));
	
        // Comment from Oleg: this is done initialy to setup correct spot in tx
        // buffer: dunno, I just believe, for now.
        if (resetTxOffset) {
            txOffset = 3;
        }

        this.reset();
        if (this.enabledL2Debug) {
            trace(" Starting IAM procedure");
        }

        // switch state
        // state = Mtp2.MTP2_NOT_ALIGNED;
        this.state = MTP2_NOT_ALIGNED;

        // starting T2 timer
        start_T2();
    }

    private void reset() {
        // reset.
        this.nCount = 0;
        this.eCount = 0;
        this.dCount = 0;

        // set proper values of FIBOS, FISSIES And other...
        this.sendFIB = 1;
        this.sendBSN = 0x7F;
        this.sendBIB = 1;
        this.retransmissionFSN = _OFF_RTR;
        this.retransmissionFSN_LastAcked = 0x7F;
        this.retransmissionFSN_LastSent = 0x7F;
    }

    public void failLink() {
        cleanupTimers();
        this.state = MTP2_OUT_OF_SERVICE;
        
        logger.info(String.format("(%s) Link Out of service", name));
        start_T17();
    }

    public boolean queue(byte[] msg) {
        if (this.state != MTP2_INSERVICE) {
            if (enableSuTrace && enabledL2Debug) {

                trace("MTP3 scheduled MSU when not in service, discarding.");
            }
            return false;
        }
        // Here we will queue MSU if there is place in transmission buffer
        int possibleFSN = NEXT_FSN(this.retransmissionFSN_LastSent);
        // check if transmission buffer is full
        if (possibleFSN == this.retransmissionFSN_LastAcked) {
            // This means buffer is full;
            if (this.enableSuTrace && enabledL2Debug) {
                trace("Failed to queue msg, transmission buffer is full.");
            }
            return false;
        }
        // FSN and all that will be set before puting this into txFrame buffer.
        this.transmissionBuffer[possibleFSN].frame[0] = 0;
        this.transmissionBuffer[possibleFSN].frame[1] = 0;
        // LI: see Q.703 2.3.3, FIXME: add check for msg.length <3 ?
        this.transmissionBuffer[possibleFSN].frame[2] = (byte) (msg.length >= 63 ? 63
                : msg.length);

        System.arraycopy(msg, 0, this.transmissionBuffer[possibleFSN].frame, 3,
                msg.length);
        //3 == FSN(1) + BSN(1) + LI(1)
        this.transmissionBuffer[possibleFSN].len = 3 + msg.length;
        // FIXME: add check for short frame?
        if (this.enableSuTrace && enabledL2Debug) {
            trace("Queue MSU");
        }
        this.retransmissionFSN_LastSent = possibleFSN;
        if (this.retransmissionFSN == _OFF_RTR) {
            this.retransmissionFSN = possibleFSN;
        }
        this.start_T7();
        // txQueue.offer(frame);
        return true;
    }

    private void queueLSSU(int indicator) {
        if (this.txLen != txOffset) {
            // we schedule in queue, this is for some special cases.
            byte[] frame = new byte[4];
            frame[0] = (byte) (this.sendBSN | (this.sendBIB << 7));
            frame[1] = (byte) (this.retransmissionFSN_LastSent | (this.sendFIB << 7));
            frame[2] = 1;
            frame[3] = (byte) indicator;
            txQueue.offer(frame);
        } else {
            this.txLen = 4;
            this.txFrame[0] = (byte) (this.sendBSN | (this.sendBIB << 7));
            this.txFrame[1] = (byte) (this.retransmissionFSN_LastSent | (this.sendFIB << 7));
            this.txFrame[2] = 1;
            this.txFrame[3] = (byte) indicator;

        }

        if (this.enableSuTrace && enabledL2Debug) {
            trace("Queue LSSU[" + FRAME_NAMES[indicator] + "]");
        }
    }

    private void queueFISU() {
        this.txLen = 3;
        this.txFrame[0] = (byte) (this.sendBSN | (this.sendBIB << 7));
        this.txFrame[1] = (byte) (this.retransmissionFSN_LastSent | (this.sendFIB << 7));
        this.txFrame[2] = 0;

        // txQueue.offer(frame);
        if (this.enableSuTrace && enabledL2Debug) {
            trace("Queue FISU");
        }
    }

    private void queueNextFrame() {
        if (this.state != MTP2_INSERVICE && !this.txQueue.isEmpty()) {
            byte[] b = txQueue.peak();
            System.arraycopy(b, 0, txFrame, 0, b.length);
            this.txLen = b.length;

        } else {
            switch (state) {
                case MTP2_OUT_OF_SERVICE:

                    // send SIOS ?
                    queueLSSU(FRAME_STATUS_INDICATION_OS);
                    break;
                case MTP2_NOT_ALIGNED:
                    queueLSSU(FRAME_STATUS_INDICATION_O);
                    break;
                case MTP2_PROVING:
                case MTP2_ALIGNED:

                    // which way is correct?
                    if (emergency) {
                        queueLSSU(FRAME_STATUS_INDICATION_E);
                    } else {
                        queueLSSU(FRAME_STATUS_INDICATION_N);
                    }
                    // if (this.T4_TIMEOUT == this.T4_TIMEOUT_EMERGENCY) {
                    // queueLSSU(FRAME_STATUS_INDICATION_E);
                    // } else {
                    //
                    // queueLSSU(FRAME_STATUS_INDICATION_N);
                    // }
                    break;

                default:

                    // in service, we need to check buffer, otherwise its RTR
                    if (this.retransmissionFSN != _OFF_RTR) {
                        Mtp2SendBuffer buffer = this.transmissionBuffer[this.retransmissionFSN];
                        // we shoudl use getters, but its faster with "."

                        System.arraycopy(buffer.frame, 0, txFrame, 0, buffer.len);
                        this.txLen = buffer.len;
                        this.txFrame[0] = (byte) (this.sendBSN | (this.sendBIB << 7));
                        this.txFrame[1] = (byte) (this.retransmissionFSN | (this.sendFIB << 7));

                        if (this.retransmissionFSN == this.retransmissionFSN_LastSent) {
                            this.retransmissionFSN = _OFF_RTR;
                        } else {
                            // set up next :)
                            this.retransmissionFSN = NEXT_FSN(this.retransmissionFSN);
                        }
                        // if (this.enabledL2Debug) {
                        // trace("Scheduled next frame in tx buffer: "
                        // + dump(this.txFrame, this.txLen, false));
                        // }
                        return;
                    }
                    // else queue FISU
                    queueFISU();
            }
        }

    }

    public final static int PPP_FCS(int fcs, int c) {
        return ((fcs) >> 8) ^ fcstab[((fcs) ^ (c)) & 0xff];
    }

    private void processLssu(int fsn, int bsn) {
        int type = rxFrame[3] & 0x07;
        //		

        switch (this.state) {
            case MTP2_NOT_ALIGNED:
                // here we wait for O/N/E
                switch (type) {
                    case FRAME_STATUS_INDICATION_O:
                    case FRAME_STATUS_INDICATION_N:
                        stop_T2();
                        if (emergency) {
                            this.T4_TIMEOUT = T4_TIMEOUT_EMERGENCY;
                            queueLSSU(FRAME_STATUS_INDICATION_E);
                        } else {
                            this.T4_TIMEOUT = T4_TIMEOUT_NORMAL;
                            queueLSSU(FRAME_STATUS_INDICATION_N);
                        }
                        start_T3();
                        this.state = MTP2_ALIGNED;
                        
                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("(%s) Aligned", name));
                        }
                        break;
                    case FRAME_STATUS_INDICATION_E:
                        // 1. stop t2
                        stop_T2();
                        // 2. set T4 time here we set always to emergency, only LSSU,
                        // differs depending on flag.
                        this.T4_TIMEOUT = T4_TIMEOUT_EMERGENCY;
                        // 3. queue response
                        if (emergency) {
                            queueLSSU(FRAME_STATUS_INDICATION_E);
                        } else {
                            queueLSSU(FRAME_STATUS_INDICATION_N);
                        }
                        // 4. start T3
                        start_T3();
                        // 5. set state
                        this.state = MTP2_ALIGNED;

                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("(%s) Aligned", name));
                        }
                        break;
                    default:
                    // logger.warn("Ingoring LSSU[" + _FRAME_NAMES[type]
                    // + "] on state[" + _STATE_NAMES[state] + "]");
                }
                // BREAK For NOT_ALIGNED state
                break;

            case MTP2_ALIGNED:

                switch (type) {
                    // Here we ignore "O"
                    case FRAME_STATUS_INDICATION_E:
                        // 1. set T4 time.
                        this.T4_TIMEOUT = Mtp2.T4_TIMEOUT_EMERGENCY;
                    case FRAME_STATUS_INDICATION_N:
                        // 1. stop T3
                        stop_T3();
                        // 2. determine threashold for AERM.
                        if (this.T4_TIMEOUT == Mtp2.T4_TIMEOUT_EMERGENCY) {
                            this.aermThreshold = Mtp2.AERM_THRESHOLD_EMERGENCY;
                        }
                        // 3. start AERM, but we do start, it works alwys? this should
                        // reset CP also?
                        startAERM();
                        // 4. start T4;
                        start_T4();
                        // 5. cp = 0;
                        this.provingAttempts = 0;
                        // 6. cancel further proving.
                        this.futureProving = false;
                        // 7. set state
                        this.state = MTP2_PROVING;
                        
                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("(%s) Proving", name));
                        }
                        break;
                    case FRAME_STATUS_INDICATION_OS:
                        // we should invoke ALI first, but we cancel timer
                        // 1. stop T3
                        stop_T3();
                        // 2. ALI not possible, this will switch to OUT_OF_SERVICE(in
                        // IAC its IDLE.) state, possibly fire OS, set T17.
                        alignmentNotPossible("Receievd SIOS in state ALIGNED");
                        // 3. cancel E
                        this.emergency = false;

                        break;
                    default:
                    // logger.warn("Ingoring LSSU[" + _FRAME_NAMES[type]
                    // + "] on state[" + _STATE_NAMES[state] + "]");
                }

                // BREAK for ALIGNED state.
                break;
            case MTP2_PROVING:
                switch (type) {
                    case FRAME_STATUS_INDICATION_O:
                        // 1. stop T4
                        stop_T4();
                        // 2. stop AERM, hmm
                        stopAERM();
                        // 3. start T3
                        start_T3();
                        // 4. swithc state
                        this.state = MTP2_ALIGNED;
                        
                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("(%s) Aligned", name));
                        }
                        break;
                    case FRAME_STATUS_INDICATION_E:
                        // NOTE: this one is not covered in Olegs src.
                        // 1. determine actions
                        if (this.T4_TIMEOUT == Mtp2.T4_TIMEOUT_EMERGENCY) {
                            // do nothing
                            return;
                        }

                        // 2. stop T4
                        stop_T4();
                        // 3. stop AERM,
                        stopAERM();
                        // 4. set AERM T
                        this.aermThreshold = Mtp2.AERM_THRESHOLD_EMERGENCY;
                        // 5. start AERM
                        startAERM();
                        // 6. Cancel Further Proving
                        this.futureProving = false;
                        // 7. start T4
                        start_T4();
                        // 8. state is still proving.

                        break;
                    case FRAME_STATUS_INDICATION_OS:
                        // 1. stop T4
                        stop_T4();
                        // 2. action;
                        // specs shows : == Aligment Complete ....
                        alignmentNotPossible("Received SIOS in state PROVING");
                        // 3. stop AERM
                        stopAERM();
                        // 4. cancel E
                        this.emergency = false;
                        // 5. should move to state IDLE, alignmentNotPossible will shift
                        // state.
                        break;
                    default:

                }
                // BREAK for PROVING state
                break;
            case MTP2_ALIGNED_READY:

                switch (type) {
                    case FRAME_STATUS_INDICATION_O:

                        // link failed.

                        // FIXME: add more state here.
                        alignmentNotPossible("Received SIO in state ALIGNED_READY");
                        break;
                    case FRAME_STATUS_INDICATION_OS:
                        // link failed, pass to MTP3?
                        // mpt3.linkFailure();
                        // FIXME: add more
                        alignmentNotPossible("Received SIOS in state ALIGNED_READY");
                    default:

                }
                //... dont forget to break!!!
                // this caused link to go down ;[
                break;
            case MTP2_INSERVICE:

                switch (type) {
                    case FRAME_STATUS_INDICATION_O:
                    case FRAME_STATUS_INDICATION_E:
                    case FRAME_STATUS_INDICATION_N:

                        // link failed, pass to MTP3?
                        // mpt3.linkFailure();
                        // FIXME: add more
                        alignmentNotPossible("Received " + FRAME_NAMES[type] + " in state IN_SERVICE");
                        break;
                    case FRAME_STATUS_INDICATION_OS:
                        // link failed, pass to MTP3?
                        // mpt3.linkFailure();
                        // FIXME: add more
                        alignmentNotPossible("Received SIOS in state IN_SERVICE");
                    default:

                }
                // BREAK for ALIGNED_READY
                break;
            default:

        }

    }

    private void processMSU(int len) {
        if (this.mtp3 != null) {
            int sio = rxFrame[3];
            int realLength = 0;
            if (len == 63) {
                // -6 = -SIO(1) - (FIB+FSN(1)) - (BIB+BSN(1)) - java(zero index: 1) -2(CRC)
                realLength = rxLen - 6;
            //was -4
            } else {
                // -1 for SIO octet, which we decode.
                realLength = len - 1;
            }

            byte[] sif = new byte[realLength];
            // for (int i = 0; i < len - 1; i++) {
            // sif[i] = (byte) rxFrame[i + 4];
            // }
            for (int i = 0; i < realLength; i++) {
                sif[i] = (byte) rxFrame[i + 4];
            }
            // FIXME: switch to this
            // System.arraycopy(rxFrame, 4, sif, 0, realLength);
            
            if (logger.isDebugEnabled()) {
        	logger.debug(String.format("(%s) Delivering MSU to layer 3 ",name));
    	    }
            mtp3.onMessage(sio, sif, this);
        }
    }

    private void processFrame() {
        int bsn = rxFrame[0] & 0x7F;
        int bib = (rxFrame[0] >> 7) & 0x01;
        int fsn = rxFrame[1] & 0x7F;
        int fib = (rxFrame[1] >> 7) & 0x01;

        int li = rxFrame[2] & 0x3f;

        if (logger.isTraceEnabled()) {
    	    String type = null;
    	    if (li == 0) {
    		type = "FISU";
    	    } else if (li == 1 || li == 2) {
    		int lssuType = rxFrame[3]&0x07;
    		type = "LSSU(" + FRAME_NAMES[lssuType]+ ")";
    	    } else {
    		type = "MSU";
    	    }
    	    logger.trace(String.format("(%s) Receive frame, type=%s, fsn=%d, fib=%d, bsn=%d, bib=%d", name, type, fsn, fib,bsn, bib));
    	    
        }
        
        //Why it was 5?
        if (li + 3 > rxLen) {

            if (this.enableSuTrace && enabledL2Debug) {
                trace("Discarding frame on wrong RX Len: " + rxLen + " > " + li);
            }
            return;
        }

        if (li == 1 || li == 2) {

            // LSSU does not count for IAM check for SU
            processLssu(fsn, bsn);
            // LSSU does not go into BSN/FSN check, its always static for this
            // part.
            // and if we get here from IN_SERVICE, everything is reset.
            return;
        }

        if (this.state != MTP2_INSERVICE) {
            switch (this.state) {
                case MTP2_PROVING:

                    // Decision;
                    if (futureProving) {
                        // 1. start AERM, maybe restart?
                        startAERM();
                        // 2. cancel FP
                        futureProving = false;
                        // 3. start T4
                        start_T4();
                    // 4. state is still proving

                    } else {
                        // 1. do nothing, stay in PROVING state,
                    }

                    // FIXME: return here?
                    break;
                case MTP2_ALIGNED_READY:

                    if (enabledL2Debug) {
                        trace("Received proper SU in ALIGNED_READY state, switching to IN_SERVICE.");
                    }
                    this.eCount = 0;
                    this.dCount = 0;
                    this.stop_T7();

                    this.sendFIB = bib;
                    this.sendBSN = fsn;
                    this.sendBIB = fib;
                    this.retransmissionFSN_LastAcked = bsn;

                    this.state = MTP2_INSERVICE;
                    
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format("(%s) MTP now IN_SERVICE, Notifing layer 3", name));
                    }
                    
                    mtp3.linkInService(this);
                    break;
            }
        }
        // Q.703 section 5.3.1 and 5.3.2, paras like:
        // If any two backward sequence number values in three consecutively
        // received message signal units or
        // fill-in signal units are not the same as the previous one or any of
        // the forward sequence number values
        // of the signal units in the retransmission buffer at the time that
        // they are received, then level 3 is
        // informed that the link is faulty.

        // This means we have to check BSN if it falls into space available for
        // rtr
        // its a bit complicated since we have "ring" buffer. where indexes are
        // reused.

        // CASE_I, buffer did not flip.
        if ((this.retransmissionFSN_LastAcked <= this.retransmissionFSN_LastSent && (bsn < this.retransmissionFSN_LastAcked || bsn > this.retransmissionFSN_LastSent)) ||
                // CASE_II, buffer flipped, lastSent is less than ack, since it
                // starts from "0"
                (this.retransmissionFSN_LastAcked > this.retransmissionFSN_LastSent && (bsn < this.retransmissionFSN_LastAcked && bsn > this.retransmissionFSN_LastSent))) {
            this.bsnErrors++;
            if (this.bsnErrors > 2) {
                this.bsnErrors = 0;
                this.mtp3.linkFailed(this);
                alignmentBroken("Broken BSN constrains: fsn_lasAcked = " + this.retransmissionFSN_LastAcked + ", fsn_LastSent = " + this.retransmissionFSN_LastSent + ", bsn = " + bsn);
            }

            return;
        }

        this.bsnErrors = 0;

        // Q.703, Section 5.3.1, T7. it is weird, its in positive section
        // but it says "ACK", any?

        if (bib == this.sendFIB) {

            if (bsn != this.retransmissionFSN_LastAcked) {

                this.stop_T7();
                this.retransmissionFSN_LastAcked = bsn;

                if (this.retransmissionFSN_LastAcked != this.retransmissionFSN_LastSent) {

                    // there is something we can retransmit, we wait for ACK
                    this.start_T7();
                }
            }
        } else {

            // negative, start rtr
            this.sendFIB = bib;
            if (bsn == this.retransmissionFSN_LastSent) {

                // there is nothing, should we error here?
                this.retransmissionFSN = _OFF_RTR;
            } else {

                this.retransmissionFSN = NEXT_FSN(bsn);
            }
        }

        if (li == 0) {

            if (fsn != this.sendBSN) {

                // something is not correctm link lost msg?
                // Q.703 section 5.2.2.a.ii
                if (fib == this.sendBIB) {

                    // flip, to make negative ACK, ask for rtr.
                    this.sendBIB = NEXT_INDICATOR(this.sendBIB);
                }
            }

        // thats it for FISU

        } else {

            if (fsn == this.sendBSN) {

                // Q.703 section 5.2.2.c.i
                // we already got this once.
                return;

            } else if (fsn == NEXT_FSN(this.sendBSN)) {

                // Q.703 section 5.2.2.c.ii
                if (fib == this.sendBIB) {

                    // positive ACK, lets send it.
                    this.sendBSN = fsn;
                } else {

                    // drop frame? since it negative?
                    return;
                }
            } else {

                // Q.703 section 5.2.2.c.iii
                // lost some frame, make negative
                if (fib == this.sendBIB) {

                    // flip, to make negative ACK, ask for rtr.
                    this.sendBIB = NEXT_INDICATOR(this.sendBIB);
                }
                return;
            }
            processMSU(li);
        }

    }

    /**
     * Handles received data.
     * 
     * @param buff
     *            the buffer which conatins received data.
     * @param len
     *            the number of received bytes.
     */
    private void processRx(byte[] buff, int len) {
        // private void processRx(ByteBuffer bb, int len) {

        int i = 0;
        // byte[] buff = bb.array();
        if (this.enableDataTrace && enabledL2Debug) {
            //dataHolder.add(new BufferHolder(System.currentTimeMillis(),	 buff,len));
            // FIXME:
//            Utils.getInstance().addBuffer(this.sls, this.name, this.linkSet.getName(), this.linkSet.getId(), System.currentTimeMillis(), buff, len);
        }
        // start HDLC alg
        while (i < len) {
            while (rxState.bits <= 24 && i < len) {
                int b = buff[i++] & 0xff;
                hdlc.fasthdlc_rx_load_nocheck(rxState, b);
                if (rxState.state == 0) {
                    // octet counting mode
                    nCount = (nCount + 1) % 16;
                    if (nCount == 0) {
                        countError("on receive");
                    }
                }
            }

            int res = hdlc.fasthdlc_rx_run(rxState);

            switch (res) {
                case FastHDLC.RETURN_COMPLETE_FLAG:
                    // frame received and we count it
                    countFrame();

                    // checking length and CRC of the received frame
                    if (rxLen == 0) {
                    } else if (rxLen < 5) {
                        // frame must be at least 5 bytes in length
                        countError("hdlc error, frame LI<5");

                    } else if (rxCRC == 0xF0B8) {
                        // good frame received
                        processFrame();
                    } else {
                        countError("hdlc complete, wrong terms.");

                    }
                    rxLen = 0;
                    rxCRC = 0xffff;
                    break;
                case FastHDLC.RETURN_DISCARD_FLAG:
                    // looking for next flag
                    rxCRC = 0xffff;
                    rxLen = 0;
                    // eCount = 0;
                    countFrame();
                    // "on receive, hdlc discard"

                    countError("hdlc discard.");

                    break;
                case FastHDLC.RETURN_EMPTY_FLAG:

                    rxLen = 0;
                    break;
                default:
                    if (rxLen > 279) {

                        rxState.state = 0;
                        rxLen = 0;
                        rxCRC = 0xffff;
                        eCount = 0;
                        countFrame();
                        countError("Overlong MTP frame, entering octet mode on link '" + name + "'");

                    } else {

                        rxFrame[rxLen++] = res;
                        rxCRC = PPP_FCS(rxCRC, res & 0xff);
                    }
            }

        }
    }

    private void processTx(int bytesRead) throws IOException {

        for (int i = 0; i < bytesRead && i < RX_TX_BUFF_SIZE; i++) {
            if (txState.bits < 8) {
                // need more bits
                if (doCRC == 0 && txOffset < txLen) {
                    int data = txFrame[txOffset++] & 0xff;
                    hdlc.fasthdlc_tx_load(txState, data);
                    txCRC = PPP_FCS(txCRC, data);
                    if (txOffset == txLen) {
                        doCRC = 1;
                        txCRC ^= 0xffff;
                    }
                } else if (doCRC == 1) {
                    hdlc.fasthdlc_tx_load_nocheck(txState, (txCRC) & 0xff);
                    doCRC = 2;
                } else if (doCRC == 2) {
                    hdlc.fasthdlc_tx_load_nocheck(txState, (txCRC >> 8) & 0xff);
                    doCRC = 0;
                } else {
                    // nextFrame();

                    queueNextFrame();

                    // txFrame = txQueue.peak();
                    // txLen = txFrame.length;
                    txOffset = 0;
                    txCRC = 0xffff;
                    hdlc.fasthdlc_tx_frame_nocheck(txState);
                }
            }
            // txBuffer.put(i, (byte) hdlc.fasthdlc_tx_run_nocheck(txState));
            txBuffer[i] = (byte) hdlc.fasthdlc_tx_run_nocheck(txState);
        }

    }

    public void run() {
	while (started) {
    	    threadTick(System.currentTimeMillis());
    	}
    }
    
    public void doRead() {
	if (started) {
	    try {
		int bytesRead = channel.read(rxBuffer);
		if (bytesRead > 0) {
		    processRx(rxBuffer, bytesRead);
		}
	    } catch (Exception e) {
		state = MTP2_OUT_OF_SERVICE;
		mtp3.linkFailed(this);
	    }
	}
    }
    
    public void doWrite() {
	if (!started) {
	    return;
	}
	try {
	    processTx(RX_TX_BUFF_SIZE);
	    channel.write(txBuffer, RX_TX_BUFF_SIZE);
	} catch (Exception e) {
	    state = MTP2_OUT_OF_SERVICE;
	    mtp3.linkFailed(this);
	}
    }
    
    public void threadTick(long tickTimeStamp) {
        if (started) {
            int bytesRead = 0;
            try {

                bytesRead = channel.read(rxBuffer);
		if (logger.isTraceEnabled()) {
		    logger.trace(String.format("(%s) Read %d bytes ", name, bytesRead));
		}
		
		//we should not break even if read returns zero because we need to write anyway!
		
                if (bytesRead > 0) {
                    // handle received data
                    processRx(rxBuffer, bytesRead);
                }
            } catch (IOException e) {
                e.printStackTrace();
                // notify MTP3 about failure.
                state = MTP2_OUT_OF_SERVICE;
                mtp3.linkFailed(this);
            } catch (Exception ee) {
                ee.printStackTrace();
                // notify MTP3 about failure.
                state = MTP2_OUT_OF_SERVICE;
                mtp3.linkFailed(this);
            }
            try {
                    processTx(RX_TX_BUFF_SIZE);
                    channel.write(txBuffer, RX_TX_BUFF_SIZE);
            } catch (IOException e) {
                e.printStackTrace();
                state = MTP2_OUT_OF_SERVICE;
                mtp3.linkFailed(this);
            } catch (Exception ee) {
                ee.printStackTrace();
                // notify MTP3 about failure.
                state = MTP2_OUT_OF_SERVICE;
                mtp3.linkFailed(this);
            }

        }


    }
    // //////////////////////////
    // PRIVATE HELPER METHODS //
    // //////////////////////////
    private void stopAERM() {
        this.aermEnabled = false;

    }

    private void startAERM() {
        this.eCount = 0;
        // we reset, for octet counting mode.
        this.nCount = 0;
        this.aermEnabled = true;

    }

    private void alignmentNotPossible(String cause) {
        this.cleanupTimers();
        this.reset();
        if (this.state == MTP2_INSERVICE) {

            if (this.mtp3 != null) {
                this.mtp3.linkFailed(this);
            }
        }
        this.state = MTP2_OUT_OF_SERVICE;
        // NOTE: buffer is flushed on start alignment.
        start_T17();

        logger.info(String.format("(%s) Alignment not possible, initiating T17 for restart. Cause: %s", name, cause));
    }

    private void alignmentBroken(String cause) {
        // FIXME: check if we can merge with above method.
        this.cleanupTimers();
        this.reset();
        if (this.state == MTP2_INSERVICE) {

            if (this.mtp3 != null) {
                this.mtp3.linkFailed(this);
            }
        }

        this.state = MTP2_OUT_OF_SERVICE;
        // NOTE: buffer is flushed on start alignment.
        start_T17();

        if (enabledL2Debug) {
            trace("Alignment broken, initiating T17 for restart. Cause: " + cause);
        }
    }

    private void cleanupTimers() {
        this.stop_T2();
        this.stop_T3();
        this.stop_T4();
        this.stop_T7();
        this.stop_T17();

    }

    private void alignmentComplete() {

        stop_T2();
        stop_T3();
        stop_T4();
        this.state = MTP2_ALIGNED_READY;
        
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("(%s) Aligned ready", name));
        }
    // now we wait for proper data
    }

    private void countError(String info) {

        eCount++;
	logger.warn(String.format("(%s) Error detected: %s", name, info));
	
        switch (state) {
            case MTP2_ALIGNED_READY:
            case MTP2_INSERVICE:
                if (eCount >= 64) {
                    if (this.mtp3 != null) {
                        mtp3.linkFailed(this);
                    }
                    state = MTP2_OUT_OF_SERVICE;
                }
                break;
            case MTP2_PROVING:
                if (this.aermEnabled) {
                    if (eCount >= aermThreshold) {
                        // start T17 ? check for alignemtn count;
                        // see Q.703 p.55
                        this.provingAttempts++;
                        if (this.provingAttempts < 5) {
                            this.futureProving = true;

                            if (enabledL2Debug) {
                                trace("Exceeded AERM threshold[ " + aermThreshold + " ] errors[ " + eCount + " ], proving attempts[ " + provingAttempts + " ]");
                            }
                            return;
                        }

                        // 1. Alignment not possible ---> ?
                        alignmentNotPossible("Exceeded AERM threshold[" + aermThreshold + "] errors[" + eCount + "], proving attempts[" + provingAttempts + "]");

                        // 2. stop T3
                        stop_T3();
                        // 3. cancel E
                        this.emergency = false;
                        // 4. stop AERM
                        stopAERM();
                    // 5. set state, should be done in #1.

                    }
                }
                break;
        }
    }

    /**
     * Increment number of received frames decrement error monitor countor for
     * each 256 good frames.
     * 
     */
    private void countFrame() {
        if (state == MTP2_ALIGNED_READY || state == MTP2_INSERVICE) {
            dCount = (dCount + 1) % 256;
            // decrement error countor for each 256 frames
            if (dCount == 0 && eCount > 0) {
                eCount--;
            }
        }
    }    // //////////////////////
    // Timers and actions //
    // //////////////////////
    private T2Action t2Action = new T2Action();
    private ScheduledFuture T2;
    private T3Action t3Action = new T3Action();
    private ScheduledFuture T3;
    private T4Action t4Action = new T4Action();
    private ScheduledFuture T4;
    private T7Action t7Action = new T7Action();
    private ScheduledFuture T7;
    private T17Action t17Action = new T17Action();
    private ScheduledFuture T17;    // Do not kill this!!!!
    private ScheduledExecutorService mtpTimer = Utils.getMtpTimer();

    private class T2Action implements Runnable {

        public void run() {
            // remove ref
            // T2.cancel(false);
            // T2 = null;
            stop_T2();
            int tmpState = state;
            if (tmpState == MTP2_NOT_ALIGNED) {
                // 1. ALI not possible
                alignmentNotPossible("T2 Expired.");
                // 2. cancel E
                emergency = false;
                if (logger.isEnabledFor(Level.WARN) && enabledL2Debug) {
                    trace("Timer T2 has expired, Alignment not possible. ");
                }
            } else {
                if (logger.isEnabledFor(Level.WARN) && enabledL2Debug) {
                    trace("T2 fired in state[ " + STATE_NAMES[tmpState] + " ]");
                }
            }
        }
    }

    private class T3Action implements Runnable {

        public void run() {
            // remove ref
            // T3.cancel(false);
            // T3 = null;
            stop_T3();
            int tmpState = state;
            if (tmpState == MTP2_ALIGNED) {
                // 1. ALI not possible
                alignmentNotPossible("T3 Expired.");
                // 2.cancel E
                emergency = false;
                if (logger.isEnabledFor(Level.WARN) && enabledL2Debug) {
                    trace("Timer T3 has expired, Alignment not possible. ");
                }
            } else {
                if (logger.isEnabledFor(Level.WARN) && enabledL2Debug) {
                    trace("T3 fired in state[ " + STATE_NAMES[tmpState] + " ]");
                }
            }
        }
    }

    private class T4Action implements Runnable {

        public void run() {

            // remove ref;
            // T4.cancel(false);
            // T4 = null;
            stop_T4();
            int tmpState = state;
            if (tmpState == MTP2_PROVING) {
                // decision
                if (futureProving) {
                    // 1. start AERM, maybe restart?
                    startAERM();
                    // 2. cancel FP
                    futureProving = false;
                    // 3. start myself :)
                    start_T4();
                // 4. state is still proving

                } else {
                    alignmentComplete();
                }
            } else {

                if (logger.isEnabledFor(Level.WARN) && enabledL2Debug) {
                    trace("T4 fired in state[ " + STATE_NAMES[tmpState] + " ]");
                }
            }
        }
    }

    private class T7Action implements Runnable {

        public void run() {
            // FIXME: add this
            stop_T7();
        }
    }

    private class T17Action implements Runnable {
        // first alig works different.
        private boolean initial = true;

        public void run() {
    	    logger.info(String.format("(%s) Restarting initial alignment", name));
            // there is somethin
            // T17.cancel(true);
            // T17 = null;
            stop_T17();
            if (state == MTP2_OUT_OF_SERVICE) {
                startInitialAlignment(initial);
            }
            if (initial) {
                initial = false;
            }

        }
    }

    private void start_T2() {
        this.stop_T2();
        this.T2 = mtpTimer.schedule(t2Action, T2_TIMEOUT, TimeUnit.MILLISECONDS);
    }

    private void stop_T2() {
        ScheduledFuture f = this.T2;
        if (f != null && !f.isCancelled()) {
    	    if (logger.isDebugEnabled()) {
                logger.debug(String.format("(%s) Kill T2", name));
            }
            this.T2 = null;
            f.cancel(false);
        }
    }

    private void start_T3() {
        this.stop_T3();
        this.T3 = mtpTimer.schedule(t3Action, T3_TIMEOUT, TimeUnit.MILLISECONDS);
    }

    private void stop_T3() {
        ScheduledFuture f = this.T3;
        if (f != null && !f.isCancelled()) {
            // logger.warn("Kill T3");
            this.T3 = null;
            f.cancel(false);
        }
    }

    private void start_T4() {
        this.stop_T4();
        this.T4 = mtpTimer.schedule(t4Action, T4_TIMEOUT, TimeUnit.MILLISECONDS);
    }

    private void stop_T4() {
        ScheduledFuture f = this.T4;
        if (f != null && !f.isCancelled()) {
            // logger.warn("Kill T4");
            this.T4 = null;
            f.cancel(false);
        }
    }

    private void start_T7() {
        this.stop_T7();
        this.T7 = mtpTimer.schedule(t7Action, T7_TIMEOUT, TimeUnit.MILLISECONDS);
    }

    private void stop_T7() {
        ScheduledFuture f = this.T7;
        if (f != null && !f.isCancelled()) {
            // logger.warn("Kill T7");
            this.T7 = null;
            f.cancel(false);
        }
    }

    // MTP3 actaully, its accessed by it, we just keep some state in mtp2
    public void start_T17() {

        this.stop_T17();
        this.T17 = mtpTimer.schedule(t17Action, T17_TIMEOUT,
                TimeUnit.MILLISECONDS);
    }

    public void stop_T17() {
        ScheduledFuture f = this.T17;
        if (f != null && !f.isCancelled()) {
            // logger.warn("Kill T17");
            this.T17 = null;
            f.cancel(false);
        }
    }

    public boolean isT17() {
        return this.T17 != null;
    }    
    
    // /////////////////////////////////////
    // Timers and Future handles for MTP 3//
    // /////////////////////////////////////
    private Runnable t1Action_SLTM = null;
    private Runnable t2Action_SLTM = null;
    
    private ScheduledFuture T1_SLTM;
    private ScheduledFuture T2_SLTM;

    public void stop_T1_SLTM() {
        ScheduledFuture f = this.T1_SLTM;
        if (f != null && !f.isCancelled()) {
            this.T1_SLTM = null;
            f.cancel(false);
        }
    }

    public void stop_T2_SLTM() {
        ScheduledFuture f = this.T2_SLTM;
        if (f != null && !f.isCancelled()) {
            this.T2_SLTM = null;
            f.cancel(false);
        }
    }

    public void start_T1_SLTM() {
        stop_T1_SLTM();
        this.T1_SLTM = mtpTimer.schedule(this.t1Action_SLTM,
                Mtp3.TIMEOUT_T1_SLTM, TimeUnit.SECONDS);
    }

    public void start_T2_SLTM() {
        stop_T2_SLTM();
        this.T2_SLTM = mtpTimer.schedule(this.t2Action_SLTM,
                Mtp3.TIMEOUT_T2_SLTM, TimeUnit.SECONDS);
    }

    public boolean isT1_SLTM() {
        return this.T1_SLTM != null;
    }

    public boolean isT2_SLTM() {
        return this.T2_SLTM != null;
    }

    public void setT1_SLTMTimerAction(Runnable r) {
        this.t1Action_SLTM = r;
    }

    public void setT2_SLTMTimerAction(Runnable r) {
        this.t2Action_SLTM = r;
    }
    /**
     * Determines if mtp should dump hex data received.
     */
    private boolean enableDataTrace = false;
    /**
     * Determines if mtp should put trace of sent/received SUs
     */
    private boolean enableSuTrace = false;
    private boolean enabledL2Debug = false;

    public boolean isL2Debug() {
        return enabledL2Debug;
    }

    public void setL2Debug(boolean l2Debug) {
        this.enabledL2Debug = l2Debug;
    }

    public boolean isEnableDataTrace() {
        return enableDataTrace;
    }

    public void setEnableDataTrace(boolean enableDataTrace) {
        this.enableDataTrace = enableDataTrace;
    }

    public boolean isEnableSuTrace() {
        return enableSuTrace;
    }

    public void setEnableSuTrace(boolean enableSuTrace) {
        this.enableSuTrace = enableSuTrace;
    }

    public void trace(String msg) {
        // FIXME: add sls
        StringBuilder sb = new StringBuilder();
        sb.append("\n").append(System.currentTimeMillis()).append(" Link [").append(name).append("] [").append(" state = ").append(
                STATE_NAMES[state]).append(" ]").append(" fsn = ").append(retransmissionFSN_LastSent).append(", fsn_acked = ").append(this.retransmissionFSN_LastAcked).append(", rtrFSN = ").append(this.retransmissionFSN).append(", fib = ").append(
                this.sendFIB).append(", bsn = ").append(this.sendBSN).append(", bib = ").append(this.sendBIB).append(") ").append(
                msg);
        Utils.getInstance().append(sb.toString());
    }

    // ////////////////////
    // Some mtp classes //
    // ////////////////////
    private class Mtp2SendBuffer {
        // FIXME: is 272 max data length?
        /**
         * data in this frame.
         */
        byte[] frame = new byte[272 + 7]; // +7 - 272 is max SIF part len, 
        /**
         * length of actual data fram to be transmited.
         */
        int len = 0;        // public boolean isFree()
        // {
        // return this.len ==0;
        // }
        // public void free()
        // {
        // this.len =0;
        // }
        // public byte[] getData()
        // {
        // return this.frame;
        // }
        // public int getLen()
        // {
        // return this.len;
        // }
    }

    private static final int NEXT_FSN(int x) {
        // kill FIB if present
        return ((x & 0x7F) + 1) % 128;
    }

    /**
     * neat way to flip indicator regardles of value.
     */
    private static final int NEXT_INDICATOR(int x) {
        return (x + 1) % 2;
    }
}
