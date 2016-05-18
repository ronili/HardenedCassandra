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

import java.io.DataInput;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.db.filter.IDiskAtomFilter;
import org.apache.cassandra.db.filter.NamesQueryFilter;
import org.apache.cassandra.db.filter.SliceQueryFilter;
import org.apache.cassandra.io.IVersionedSerializer;
import org.apache.cassandra.io.util.DataOutputPlus;
import org.apache.cassandra.net.MessageOut;
import org.apache.cassandra.net.MessagingService;
import org.apache.cassandra.service.IReadCommand;
import org.apache.cassandra.service.RowDataResolver;
import org.apache.cassandra.service.pager.Pageable;

import cs.technion.ByzantineConfig;
import cs.technion.ByzantineTools;

public abstract class ReadCommand implements IReadCommand, Pageable
{
	public String ts;
	public String columns;
	public String clientName;
	
	// Should not be sent to node
	public List<String> blackList;
	
	public enum Type
    {
        GET_BY_NAMES((byte)1),
        GET_SLICES((byte)2);

        public final byte serializedValue;

        private Type(byte b)
        {
            this.serializedValue = b;
        }

        public static Type fromSerializedValue(byte b)
        {
            return b == 1 ? GET_BY_NAMES : GET_SLICES;
        }
    }

    public static final ReadCommandSerializer serializer = new ReadCommandSerializer();

    public MessageOut<ReadCommand> createMessage()
    {
        return new MessageOut<>(MessagingService.Verb.READ, this, serializer);
    }

    public final String ksName;
    public final String cfName;
    public ByteBuffer key;
    public final long timestamp;
    private boolean isDigestQuery = false;
    protected final Type commandType;

    protected ReadCommand(String ksName, ByteBuffer key, String cfName, long timestamp, Type cmdType)
    {
        this.ksName = ksName;
        this.key = key;
        this.cfName = cfName;
        this.timestamp = timestamp;
        this.commandType = cmdType;
    }

    public static ReadCommand create(String ksName, ByteBuffer key, String cfName, long timestamp, IDiskAtomFilter filter)
    {
        if (filter instanceof SliceQueryFilter)
            return new SliceFromReadCommand(ksName, key, cfName, timestamp, (SliceQueryFilter)filter);
        else
            return new SliceByNamesReadCommand(ksName, key, cfName, timestamp, (NamesQueryFilter)filter);
    }

    public boolean isDigestQuery()
    {
        return isDigestQuery;
    }

    public ReadCommand setIsDigestQuery(boolean isDigestQuery)
    {
        this.isDigestQuery = isDigestQuery;
        return this;
    }

    public String getColumnFamilyName()
    {
        return cfName;
    }

    public abstract ReadCommand copy();

    public abstract Row getRow(Keyspace keyspace);

    public abstract IDiskAtomFilter filter();

    public String getKeyspace()
    {
        return ksName;
    }

    // maybeGenerateRetryCommand is used to generate a retry for short reads
    public ReadCommand maybeGenerateRetryCommand(RowDataResolver resolver, Row row)
    {
        return null;
    }

    // maybeTrim removes columns from a response that is too long
    public Row maybeTrim(Row row)
    {
        return row;
    }

    public long getTimeout()
    {
        return DatabaseDescriptor.getReadRpcTimeout();
    }
}

class ReadCommandSerializer implements IVersionedSerializer<ReadCommand>
{
    public void serialize(ReadCommand command, DataOutputPlus out, int version) throws IOException
    {
        out.writeByte(command.commandType.serializedValue);
        switch (command.commandType)
        {
            case GET_BY_NAMES:
                SliceByNamesReadCommand.serializer.serialize(command, out, version);
                break;
            case GET_SLICES:
                SliceFromReadCommand.serializer.serialize(command, out, version);
                break;
            default:
                throw new AssertionError();
        }
        
        if (ByzantineConfig.isSignaturesLogic && 
        	ByzantineTools.isRelevantKeySpace(command.ksName)) {
        	out.writeUTF(command.ts);
        	out.writeUTF(command.columns);
        	if (ByzantineConfig.isMacSignatures) {
        		out.writeUTF(command.clientName);
        	}
        }
    }

    public ReadCommand deserialize(DataInput in, int version) throws IOException
    {
        ReadCommand.Type msgType = ReadCommand.Type.fromSerializedValue(in.readByte());
       
        ReadCommand rc;
        switch (msgType)
        {
            case GET_BY_NAMES:
                rc = SliceByNamesReadCommand.serializer.deserialize(in, version);
                break;
            case GET_SLICES:
                rc = SliceFromReadCommand.serializer.deserialize(in, version);
                break;
            default:
                throw new AssertionError();
        }
        
        if (ByzantineConfig.isSignaturesLogic && 
        	ByzantineTools.isRelevantKeySpace(rc.ksName)) {
        	rc.ts 	   =  in.readUTF();
        	rc.columns =  in.readUTF();
        	if (ByzantineConfig.isMacSignatures) {
        		rc.clientName = in.readUTF();
        	}
        }
        
        return rc;
    }

    public long serializedSize(ReadCommand command, int version)
    {
    	long size = 0;
        switch (command.commandType)
        {
            case GET_BY_NAMES:
                size = 1 + SliceByNamesReadCommand.serializer.serializedSize(command, version);
                break;
            case GET_SLICES:
                size = 1 + SliceFromReadCommand.serializer.serializedSize(command, version);
                break;
            default:
                throw new AssertionError();
        }
        
        if (ByzantineConfig.isSignaturesLogic && 
        	ByzantineTools.isRelevantKeySpace(command.ksName)) {
        	TypeSizes typeSizes = TypeSizes.NATIVE;
        	size += typeSizes.sizeof(command.ts);
        	size += typeSizes.sizeof(command.columns);
        	if (ByzantineConfig.isMacSignatures) {
        		size += typeSizes.sizeof(command.clientName);
        	}
        }
        
        return size;
    }
}
