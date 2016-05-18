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
package org.apache.cassandra.db;

import org.apache.cassandra.net.IVerbHandler;
import org.apache.cassandra.net.MessageIn;
import org.apache.cassandra.net.MessageOut;
import org.apache.cassandra.net.MessagingService;
import org.apache.cassandra.service.StorageService;
import org.apache.cassandra.tracing.Tracing;
import org.apache.cassandra.utils.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cs.technion.ByzantineConfig;
import cs.technion.ByzantineTools;
import cs.technion.ByzantineCommands;
import cs.technion.ByzantineTools.NodeSignature;

public class ReadVerbHandler implements IVerbHandler<ReadCommand>
{
    private static final Logger logger = LoggerFactory.getLogger(MutationVerbHandler.class);
    
    public void doVerb(MessageIn<ReadCommand> message, int id)
    {
        if (StorageService.instance.isBootstrapMode())
        {
            throw new RuntimeException("Cannot service reads while bootstrapping!");
        }
        

        ReadCommand command = message.payload;
        Keyspace keyspace = Keyspace.open(command.ksName);
        Row row = command.getRow(keyspace);
        
        MessageOut<ReadResponse> reply = new MessageOut<ReadResponse>(MessagingService.Verb.REQUEST_RESPONSE,
														              getResponse(command, row),
														              ReadResponse.serializer);
        
        if (ByzantineConfig.isSignaturesLogic && ByzantineTools.isRelevantKeySpace(command.ksName)) {
        	String ts = command.ts;
        	String clientId = command.clientName;
        	String columns = command.columns;
        	
        	if (ByzantineConfig.isInfoLogger)
        		logger.info("[ronili] Node is handling read request for: {} : {} is digest = {} + colums = {} + ts = {} + clientID = {}",
        				command.ksName, new String(command.key.array()),command.isDigestQuery(), columns, ts, clientId);
        	
        	NodeSignature signature = null;

        	if (!ByzantineConfig.isCommandPath) {
        		signature = ByzantineTools.computeNodeSignature(row, logger, ts, clientId, columns);
        	} else {
		        if (ByzantineCommands.shouldIgnoreThisRead(command, logger)){
		    		return;
		    	}
	     
	        	boolean shouldReturnBadSignRead = ByzantineCommands.shouldReturnBadSignRead(command, logger);
	        	boolean shouldReturnBadDigest = ByzantineCommands.shouldReturnBadDigest(command, logger);
	        	
	        	signature = new NodeSignature();
	        	
	        	// Will mark this answer as Byzantine
	        	if (shouldReturnBadSignRead) {
	        		signature.clientSign = "non-client";
	        		signature.extenedNodeSign = ByzantineTools.getNonValidReadSign();
	        	// Will produce a mismatch exception
	        	} else if (shouldReturnBadDigest) {
	        		String clientNonSign = "non-client sign";
	        		signature.clientSign = clientNonSign;
	        		signature.extenedNodeSign = ByzantineTools.computeNodeSignature(new String(command.key.array()), clientNonSign, logger, ts, clientId);
	        	} else {
	        		// Good behavior
	        		signature = ByzantineTools.computeNodeSignature(row, logger, ts, clientId, columns);
	        	}
        	}
        	
        	ReadResponse response = (ReadResponse)reply.payload;
        	if (signature != null &&
        		signature.clientSign != null &&
        		signature.extenedNodeSign != null) {
        		response.clientSign = signature.clientSign;
        		response.signature = signature.extenedNodeSign;
        		if (command.isDigestQuery() && 
        			signature.hvals != null) {
        			response.hash = signature.hvals;
        		}
        		
	        	if (ByzantineConfig.isInfoLogger)
	        		logger.info("[ronili] read answer: clientSign = {} + signature = {} hash {}",
	        				response.clientSign, response.signature, response.hash);
	        	
        		
            } else {
            	response.signature = ByzantineTools.computeEmptySignature(new String(command.key.array()), logger, ts, clientId);
            	if (response.signature == null) {
            		if (ByzantineConfig.isErrorLogger)
    	        		logger.error("[ronili] got null from computeEmptySignature");
            		response.signature = "";
            	}
        	}
        }
             
        Tracing.trace("Enqueuing response to {}", message.from);
        MessagingService.instance().sendReply(reply, id, message.from);
    }

    public static ReadResponse getResponse(ReadCommand command, Row row)
    {
        if (command.isDigestQuery())
        {
            return new ReadResponse(ColumnFamily.digest(row.cf));
        }
        else
        {
            return new ReadResponse(row);
        }
    }
}
