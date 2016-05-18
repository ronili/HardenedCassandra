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

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.cassandra.db.DecoratedKey;
import org.apache.cassandra.db.ReadResponse;
import org.apache.cassandra.db.Row;
import org.apache.cassandra.net.MessageIn;
import org.apache.cassandra.utils.Pair;
import org.apache.cassandra.utils.concurrent.Accumulator;

import cs.technion.ByzantineConfig;
import cs.technion.ByzantineTools;

public abstract class AbstractRowResolver implements IResponseResolver<ReadResponse, Row>
{
	protected List<Pair<String,String> > signaturesList = null;
	protected static final Logger logger = LoggerFactory.getLogger(AbstractRowResolver.class);
	
	public String getSignatures(){
		String temp = null;	
		synchronized (signaturesList) {
			for (Pair<String,String> p : signaturesList) {
				temp = ByzantineTools.safeConcat(temp, p.right);
			}
		}
		
		return temp;
	}
	
	public List<Pair<String,String> > getSignaturesList(){
		List<Pair<String,String>> temp = new ArrayList<Pair<String,String>>(signaturesList.size());
		synchronized (signaturesList) {
			temp.addAll(signaturesList);
		}
		return temp;
	}
	
	protected void appendToSignaturesList(String clientSign, String sign){
		appendToSignaturesList(Pair.create(clientSign, sign));
	}
	
	protected void appendToSignaturesList(Pair<String,String> s){
		if (s == null) {
			return;
		}
		
		synchronized (signaturesList) {
			signaturesList.add(s);
		}
	}
	
	protected void computeAndSetAllSignatures() {
		
		int i = 0;
		for (MessageIn<ReadResponse> message : replies) {
    		ReadResponse result = message.payload;
    		String clientSign = result.clientSign;
    		String sign = result.signature + ":" + message.from;
    	
    		if (sign == null || sign.equals("")) {
    			continue;
    		}
    		
    		i++;
    		appendToSignaturesList(Pair.create(clientSign, sign));
        }
		
		if (ByzantineConfig.isInfoLogger)
			logger.info("Collected {} responses", i);
    }
	
    protected final String keyspaceName;
    // Accumulator gives us non-blocking thread-safety with optimal algorithmic constraints
    protected final Accumulator<MessageIn<ReadResponse>> replies;
    protected final DecoratedKey key;

    public AbstractRowResolver(ByteBuffer key, String keyspaceName, int maxResponseCount)
    {
        this.key = StorageService.getPartitioner().decorateKey(key);
        this.keyspaceName = keyspaceName;
        this.replies = new Accumulator<>(maxResponseCount);
        
        if (ByzantineConfig.isSignaturesLogic) {
        	this.signaturesList = new LinkedList<Pair<String,String>>();
        }
    }

    public void preprocess(MessageIn<ReadResponse> message)
    {
        replies.add(message);
    }

    public Iterable<MessageIn<ReadResponse>> getMessages()
    {
        return replies;
    }
}
