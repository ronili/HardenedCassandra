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

import java.io.DataInputStream;
import java.io.IOException;
import java.net.InetAddress;

import org.apache.cassandra.io.util.FastByteArrayInputStream;
import org.apache.cassandra.net.*;
import org.apache.cassandra.tracing.Tracing;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cs.technion.ByzantineCommands;
import cs.technion.ByzantineConfig;
import cs.technion.ByzantineTools;

public class MutationVerbHandler implements IVerbHandler<Mutation>
{
    private static final boolean TEST_FAIL_WRITES = System.getProperty("cassandra.test.fail_writes", "false").equalsIgnoreCase("true");

    //ronili
    private static final Logger logger = LoggerFactory.getLogger(MutationVerbHandler.class);

	public void doVerb(MessageIn<Mutation> message, int id) throws IOException 
	{
		// Check if there were any forwarding headers in this message
		byte[] from = message.parameters.get(Mutation.FORWARD_FROM);
		InetAddress replyTo;
		if (from == null) {
			replyTo = message.from;
			byte[] forwardBytes = message.parameters.get(Mutation.FORWARD_TO);
			if (forwardBytes != null)
				forwardToLocalNodes(message.payload, message.verb, forwardBytes, message.from);
		} else {
			replyTo = InetAddress.getByAddress(from);
		}
		
		if (!ByzantineConfig.isSignaturesLogic) {
			message.payload.apply();
			WriteResponse response = new WriteResponse();
			Tracing.trace("Enqueuing response to {}", replyTo);
			MessagingService.instance().sendReply(response.createMessage(), id, replyTo);
			return;
		}

		if (ByzantineConfig.isCommandPath) {
			if (ByzantineCommands.handleCommandPath(message.payload.getKeyspaceName(),	message.payload, logger)) {
				if (ByzantineConfig.isInfoLogger) {
					logger.info("[ronili] Command completed, returning.");
				}
				WriteResponse response = new WriteResponse();
				MessagingService.instance().sendReply(response.createMessage(), id, replyTo);
				return;
			}
		}

		String symmetricSign = null;
		if (ByzantineConfig.isFullMACSignatures && 
			ByzantineTools.isRelevantKeySpace(message.payload.getKeyspaceName())) {
			if (!message.payload.symmetricSign.isEmpty()) {
				symmetricSign = message.payload.symmetricSign;
				if (ByzantineConfig.isInfoLogger) {
					logger.info("[ronili] Got symmetric sign {}", symmetricSign);
				} 
			} else {
				if (ByzantineConfig.isInfoLogger) {
					logger.info("[ronili] no symmetric sign.");
				}
			}
		}
		
		byte[] sign = ByzantineTools.checkMutationSignature(message.payload, logger, symmetricSign);

		if (sign == null) {
			if (ByzantineConfig.isErrorLogger) 
				logger.error("[ronili] Byzantine verification faild");
			return;
		} 
		
		// Apply the change.
		if (ByzantineConfig.isInfoLogger) 
			logger.info("[ronili] Mutation verified");

		if (ByzantineConfig.isCommandPath) {
			boolean shouldIgnoreThisWriteLoud = ByzantineCommands.shouldIgnoreThisWriteLoud(message.payload, logger);
			boolean shouldIgnoreThisWriteSilence = ByzantineCommands.shouldIgnoreThisWriteSilence(message.payload,logger);
			boolean shouldReturnBadSign = ByzantineCommands.shouldReturnBadSignWrite(message.payload, logger);
			if (!shouldIgnoreThisWriteSilence && !shouldIgnoreThisWriteLoud && !shouldReturnBadSign) {
				message.payload.apply();
			} else {
				if (ByzantineConfig.isInfoLogger) 
					logger.info("[ronili] Skipping this insert due to command request.");
			}
			
			if (!shouldIgnoreThisWriteLoud) {
				WriteResponse response = new WriteResponse();
				response.signature = new String(sign);
				response.signer = ByzantineTools.getNodeName();
				
				if (shouldReturnBadSign) {
					if (ByzantineConfig.isInfoLogger) 
						logger.info("[ronili] sending bad signature back");	
					response.signature = "no-sign";
				}
				
				MessagingService.instance().sendReply(response.createMessage(), id,	replyTo);

				if (ByzantineConfig.isInfoLogger) 
					logger.info("[ronili] sending write signature back");					
			} else {
				if (ByzantineConfig.isInfoLogger) 
					logger.info("[ronili] Not sending write signature back due to command request.");
			}
		} else {
			message.payload.apply();
			WriteResponse response = new WriteResponse();
			response.signature = new String(sign);
			response.signer = ByzantineTools.getNodeName();
			MessagingService.instance().sendReply(response.createMessage(), id,	replyTo);
		}
	}

    /**
     * Older version (< 1.0) will not send this message at all, hence we don't
     * need to check the version of the data.
     */
    private void forwardToLocalNodes(Mutation mutation, MessagingService.Verb verb, byte[] forwardBytes, InetAddress from) throws IOException
    {
        try (DataInputStream in = new DataInputStream(new FastByteArrayInputStream(forwardBytes)))
        {
            int size = in.readInt();

            // tell the recipients who to send their ack to
            MessageOut<Mutation> message = new MessageOut<>(verb, mutation, Mutation.serializer).withParameter(Mutation.FORWARD_FROM, from.getAddress());
            // Send a message to each of the addresses on our Forward List
            for (int i = 0; i < size; i++)
            {
                InetAddress address = CompactEndpointSerializationHelper.deserialize(in);
                int id = in.readInt();
                Tracing.trace("Enqueuing forwarded write to {}", address);
                MessagingService.instance().sendOneWay(message, id, address);
            }
        }
    }
}
