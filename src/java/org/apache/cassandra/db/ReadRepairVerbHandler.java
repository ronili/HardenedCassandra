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

import org.apache.cassandra.net.AsyncOneResponse;
import org.apache.cassandra.net.IVerbHandler;
import org.apache.cassandra.net.MessageIn;
import org.apache.cassandra.net.MessagingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cs.technion.ByzantineConfig;
import cs.technion.ByzantineTools;
import cs.technion.ByzantineCommands;

public class ReadRepairVerbHandler implements IVerbHandler<Mutation>
{
    private static final Logger logger = LoggerFactory.getLogger(AsyncOneResponse.class);

    public void doVerb(MessageIn<Mutation> message, int id)
    {
    	if (!ByzantineConfig.isSignaturesLogic || !ByzantineTools.isRelevantKeySpace(message.payload.getKeyspaceName())){
    		message.payload.apply();
    		WriteResponse response = new WriteResponse();
    		MessagingService.instance().sendReply(response.createMessage(), id, message.from);
    		return;
    	}
    	
    	boolean shouldReturnBadSign = false;
    	if(ByzantineConfig.isCommandPath) {
    		boolean shouldIgnoreThisWriteLoud = ByzantineCommands.shouldIgnoreThisWriteLoud(message.payload, logger);
    		shouldReturnBadSign = ByzantineCommands.shouldReturnBadSignWrite(message.payload, logger);  		
    		
    		if (shouldIgnoreThisWriteLoud) {
    			if (ByzantineConfig.isInfoLogger)
    				logger.info("[ronili] Not sending back RR write back signature due to command.");
    			return;
    		}
    	}
    	
    	String ts = message.payload.ts;
    	String clientId = message.payload.clientId;
    	String columns = message.payload.columns;
    	
    	String sign = ByzantineTools.checkMutationSignatureWithTSAndWB(message.payload, logger, ts, clientId, columns);
		if (sign != null) {
			message.payload.apply();
			WriteResponse response = new WriteResponse();
			response.signature = sign;
			
    		if (ByzantineConfig.isCommandPath && shouldReturnBadSign) {
    			if (ByzantineConfig.isInfoLogger)
    				logger.info("[ronili]  sending bad signature back");
    			response.signature = "no-sign";
    		}

			MessagingService.instance().sendReply(response.createMessage(), id, message.from);
			if (ByzantineConfig.isInfoLogger)
				logger.info("[ronili] Mutation verified Write back (Read Reapir)");
		} else {
			if (ByzantineConfig.isErrorLogger)
				logger.error("[ronili] Byzantine verification faild in Write back (Read Reapir)");
		}
    }
}
