/*
 * This is a modified version of AsyncOneResponse that lets you wait
 * for any number of responses and not just one. Similar to ReadCallback.
 */
package cs.technion;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;

import org.apache.cassandra.db.WriteResponse;
import org.apache.cassandra.net.IAsyncCallback;
import org.apache.cassandra.net.MessageIn;
import org.apache.cassandra.utils.concurrent.SimpleCondition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cs.technion.ByzantineTools;

/**
 * A callback specialized for returning a value from a single target; that is,
 * this is for messages that we only send to one recipient.
 */
public class AsyncAllResponses<T> implements IAsyncCallback<T> {
	private Boolean done = false;
	private final long start = System.nanoTime();

	private String key;
	private String clientSign;
	private String keySpace;
	private String ts;
	private String hvals;
	final int blockFor;
	final int maxAcceptedFailures;
	private boolean failed = false;
	private List<String> signatures = new LinkedList<String>();

	protected volatile int received;
	private static final AtomicIntegerFieldUpdater<AsyncAllResponses> 
		recievedUpdater = AtomicIntegerFieldUpdater
			.newUpdater(AsyncAllResponses.class, "received");

	protected volatile int failures;
	private static final AtomicIntegerFieldUpdater<AsyncAllResponses> 
		failuresUpdater = AtomicIntegerFieldUpdater
			.newUpdater(AsyncAllResponses.class, "failures");

	private final SimpleCondition condition = new SimpleCondition();

	private static final Logger logger = LoggerFactory
			.getLogger(AsyncAllResponses.class);

	public AsyncAllResponses(String clientSign, String keySpace, int blockFor, int totalSent, String key, String ts, String hvals) {
		super();
		this.clientSign = clientSign;
		this.keySpace = keySpace;
		this.blockFor = blockFor;
		this.maxAcceptedFailures = totalSent - blockFor;
		this.key = key;
		this.ts = ts;
		this.hvals = hvals;

		assert maxAcceptedFailures >= 0;
	}

	public boolean await(long timePastStart, TimeUnit unit) {
		long time = unit.toNanos(timePastStart) - (System.nanoTime() - start);
		try {
			return condition.await(time, TimeUnit.NANOSECONDS);
		} catch (InterruptedException ex) {
			throw new AssertionError(ex);
		}
	}

	// Timeout in MILLISECONDS
	public List<String> get(long timeout) throws TimeoutException {
		if (blockFor <= 0) {
			return Collections.emptyList();
		}

		if (!await(timeout, TimeUnit.MILLISECONDS)) {
			synchronized (done) {
				done = true;
			}
			if (ByzantineConfig.isErrorLogger)
				logger.error("Throwing timeout.");
			throw new TimeoutException("Operation timed out.");
		}

		if (failed) {
			throw new TimeoutException("To many failures.");
		}

		List<String> safeList = new LinkedList<String>();
		
		synchronized (signatures) {
			safeList.addAll(signatures);
		}
		return safeList;
	}

	public void response(MessageIn<T> response) {
		synchronized (done) {
			if (done) {
				return;
			}
		}

		T result = response.payload;

		boolean isMessageVerifiedByzantine = true;
		if (!ByzantineConfig.isReadOption2) {
			isMessageVerifiedByzantine = ByzantineTools
					.isMessageVerifiedWriteBack(response, key, logger, keySpace, clientSign, ts, hvals);
		}

		if (isMessageVerifiedByzantine) {
			String signature = ((WriteResponse) result).signature;
			synchronized (signatures) {
				signatures.add(signature + ":" + response.from);
			}
			
			if (ByzantineConfig.isInfoLogger)
				logger.info("Write back verified " + response.from);

			if (recievedUpdater.incrementAndGet(this) >= blockFor) {
				synchronized (done) {
					done = true;
				}
				signal();
			}
		} else {
			if (ByzantineConfig.isErrorLogger)
				logger.error("Write back verification failed " + response.from);

			if (failuresUpdater.incrementAndGet(this) >= maxAcceptedFailures) {
				synchronized (done) {
					done = true;
					failed = true;
				}
				signal();
			}
		}
	}

	void signal() {
		condition.signalAll();
	}

	public boolean isLatencyForSnitch() {
		return false;
	}
}
