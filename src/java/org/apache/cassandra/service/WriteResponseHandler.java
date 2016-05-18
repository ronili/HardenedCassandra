/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.cassandra.service;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.cassandra.db.Keyspace;
import org.apache.cassandra.net.MessageIn;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.db.WriteResponse;
import org.apache.cassandra.db.WriteType;
import org.apache.cassandra.db.marshal.BytesType;
import org.apache.cassandra.db.marshal.UTF8Type;

import cs.technion.ByzantineConfig;
import cs.technion.ByzantineTools;

/**
 * Handles blocking writes for ONE, ANY, TWO, THREE, QUORUM, and ALL consistency levels.
 */
public class WriteResponseHandler<T> extends AbstractWriteResponseHandler<T>
{
    protected static final Logger logger = LoggerFactory.getLogger(WriteResponseHandler.class);

    protected volatile int responses;
    private static final AtomicIntegerFieldUpdater<WriteResponseHandler> responsesUpdater
            = AtomicIntegerFieldUpdater.newUpdater(WriteResponseHandler.class, "responses");
    
    public WriteResponseHandler(Collection<InetAddress> writeEndpoints,
                                Collection<InetAddress> pendingEndpoints,
                                ConsistencyLevel consistencyLevel,
                                Keyspace keyspace,
                                Runnable callback,
                                WriteType writeType)
    {
        super(keyspace, writeEndpoints, pendingEndpoints, consistencyLevel, callback, writeType);
        responses = totalBlockFor();
        if (ByzantineConfig.isSignaturesLogic) {
        	this.signatures = Collections.synchronizedList(new ArrayList<List<ByteBuffer>>());
        }
    }
    
    public void setResponses(Integer num) {
    	responses = num;
    }

    public WriteResponseHandler(InetAddress endpoint, WriteType writeType, Runnable callback)
    {
        this(Arrays.asList(endpoint), Collections.<InetAddress>emptyList(), ConsistencyLevel.ONE, null, callback, writeType);
    }

    public WriteResponseHandler(InetAddress endpoint, WriteType writeType)
    {
        this(endpoint, writeType, null);
    }
    
    public void response(MessageIn<T> m)
    {
    	if (!ByzantineConfig.isSignaturesLogic) {
    		if (responsesUpdater.decrementAndGet(this) == 0)
                signal();
    		
    		return;
    	}
    	
    	// ronili: this is a local write which is not our.
    	if (m == null || !ByzantineTools.isRelevantKeySpace(keyspace)) {
    		if (responsesUpdater.decrementAndGet(this) == 0)
                signal();
    		
    		return;
    	}
    	
    	WriteResponse wr = (WriteResponse)m.payload;
    	String signature = wr.signature;
    	String signerId = wr.signer;
    	
    	if (ByzantineConfig.isInfoLogger) 
    		logger.info("[ronili] got WriteResponse from " + m.from + ", Signer is:" + signerId);
    	
    	// Option 1: Verify signature
    	// Option 2: Skip verification
    	if (!ByzantineConfig.isWriteOption2) { 
    		if (!ByzantineTools
    				.isWriteResponseVerified(signerId, signature, clientSignature, logger)) {
    			return;
    		}
    		
    		if (ByzantineConfig.isInfoLogger) 
    			logger.error("[ronili] signature is not trivial, counting.");
    	}
		
		if (ByzantineConfig.isWriteOption2) { 
			responseWithSignature(signature.getBytes(), signerId, m.from.toString());
		} else {
			responseWithSignature(signature.getBytes(), signerId);
		}
    }
    
    // ronili - Adds a row with a signature from a node. 
    // 			Being called also from outside
    @Override
    public void responseWithSignature(byte[] sign, String fromId)
    {
    	List<ByteBuffer> data = new ArrayList<ByteBuffer>(2);
    	data.add(BytesType.instance.decompose(ByteBuffer.wrap(sign)));
    	data.add(UTF8Type.instance.decompose(fromId));
		signatures.add(data);
		
        if (responsesUpdater.decrementAndGet(this) == 0)
            signal();
    }
    
    // ronili - Adds a row with a signature from a node. 
    // 			Being called also from outside
    @Override
    public void responseWithSignature(byte[] sign, String fromId, String fromAddr)
    {
    	List<ByteBuffer> data = new ArrayList<ByteBuffer>(3);
    	data.add(BytesType.instance.decompose(ByteBuffer.wrap(sign)));
    	data.add(UTF8Type.instance.decompose(fromId));
    	data.add(UTF8Type.instance.decompose(fromAddr));
		signatures.add(data);
		
        if (responsesUpdater.decrementAndGet(this) == 0)
            signal();
    }

    protected int ackCount()
    {
        return totalBlockFor() - responses;
    }

    public boolean isLatencyForSnitch()
    {
        return false;
    }
}
