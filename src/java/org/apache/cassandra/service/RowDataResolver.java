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
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.google.common.collect.Iterables;

import cs.technion.AsyncAllResponses;
import cs.technion.ByzantineConfig;
import cs.technion.ByzantineTools;
import cs.technion.ByzantineTools.MetaVal;

import org.apache.cassandra.config.CFMetaData;
import org.apache.cassandra.config.Schema;
import org.apache.cassandra.cql3.ColumnIdentifier;
import org.apache.cassandra.db.*;
import org.apache.cassandra.db.columniterator.IdentityQueryFilter;
import org.apache.cassandra.db.composites.CellName;
import org.apache.cassandra.db.composites.CellNames;
import org.apache.cassandra.db.filter.IDiskAtomFilter;
import org.apache.cassandra.db.filter.QueryFilter;
import org.apache.cassandra.net.*;
import org.apache.cassandra.tracing.Tracing;
import org.apache.cassandra.utils.CloseableIterator;
import org.apache.cassandra.utils.FBUtilities;
import org.slf4j.Logger;

public class RowDataResolver extends AbstractRowResolver
{
    private int maxLiveCount = 0;
    public List<AsyncOneResponse> repairResults = Collections.emptyList();
    private final IDiskAtomFilter filter;
    private final long timestamp;
    
    public String clientSign;
    public String ts;
    public String clientId;
    public String columns;
    
    private List<InetAddress> allRelevantEndpoints;
    private ConsistencyLevel consistencyLevel;
    public AsyncAllResponses writeBackHandler;
    
    public RowDataResolver(
    		String keyspaceName, 
    		ByteBuffer key, 
    		IDiskAtomFilter qFilter, 
    		long timestamp, 
    		int maxResponseCount,
    		String ts,
    		String clientId,
    		String columns)
    {
        super(key, keyspaceName, maxResponseCount);
        this.filter = qFilter;
        this.timestamp = timestamp;
        
        if (ByzantineConfig.isSignaturesLogic) {
        	this.ts = ts;
            this.clientId = clientId;
            this.columns = columns;
        }
    }

    public RowDataResolver(
    		String keyspaceName, 
    		ByteBuffer key, 
    		IDiskAtomFilter qFilter, 
    		long timestamp, 
    		int maxResponseCount, 
    		List<InetAddress> allRelevantEndpoints,
    		ConsistencyLevel consistencyLevel,
    		String ts,
    		String clientId,
    		String columns)
    {
        super(key, keyspaceName, maxResponseCount);
        this.filter = qFilter;
        this.timestamp = timestamp;
        this.allRelevantEndpoints = allRelevantEndpoints;
        this.consistencyLevel = consistencyLevel;
    	this.ts = ts;
        this.clientId = clientId;
        this.columns = columns;
    }
    
    public List<Row> getAllRowsInjected() {
    	List<Row> rows = new LinkedList<Row>();
		
    	for (MessageIn<ReadResponse> message : replies) {
		    ReadResponse response = message.payload;
		    Row row = response.row();
		    ByzantineTools.injectGivenSignature(
		    		response.signature + ":" + message.from, 
		    		row, 
		    		logger);
		    rows.add(row);
		}
    	
    	return rows;
    }
    
    /*
    * This method handles the following scenario:
    *
    * there was a mismatch on the initial read, so we redid the digest requests
    * as full data reads.  In this case we need to compute the most recent version
    * of each column, and send diffs to out-of-date replicas.
    */
	@SuppressWarnings("unused")
	public Row resolve() throws DigestMismatchException
    {
		// In this case the client will resolve this
		if (ByzantineConfig.isSignaturesLogic &&
            ByzantineConfig.isReadOption2b &&
            ByzantineTools.isRelevantKeySpace(keyspaceName)) {
			return null;
		}
		
        int replyCount = replies.size();
        if (logger.isTraceEnabled())
            logger.trace("resolving {} responses", replyCount);
        long start = System.nanoTime();

        ColumnFamily resolved = null;
        if (replyCount > 1)
        {
            List<ColumnFamily> versions = new ArrayList<>(replyCount);
            List<InetAddress> endpoints = new ArrayList<>(replyCount);
            List<String> clientSigns;
            
            if (ByzantineConfig.isSignaturesLogic) {
            	clientSigns = new ArrayList<>(replyCount);
            }
            for (MessageIn<ReadResponse> message : replies)
            {
                ReadResponse response = message.payload;
                ColumnFamily cf = response.row().cf;
                assert !response.isDigestQuery() : "Received digest response to repair read from " + message.from;
                versions.add(cf);
                endpoints.add(message.from);
                
                if (ByzantineConfig.isSignaturesLogic) {
                	clientSigns.add(response.clientSign);
                }
                
                // compute maxLiveCount to prevent short reads -- see https://issues.apache.org/jira/browse/CASSANDRA-2643
                int liveCount = cf == null ? 0 : filter.getLiveCount(cf, timestamp);
                if (liveCount > maxLiveCount)
                    maxLiveCount = liveCount;
            }

            if (ByzantineConfig.isSignaturesLogic || 
            	ByzantineConfig.isDataPathLogic) {
            	if (ByzantineTools.isRelevantKeySpace(keyspaceName)) {
            		resolved = byzantineResolver(versions, key);
                    
                	if (resolved != null) {
                        clientSign = ByzantineTools.getClientSigns(resolved);
                        writeBackHandler = byzantineScheduleRepairs(
                    			resolved, 
                    			keyspaceName, 
                    			key, 
                    			endpoints, 
                    			clientSign, 
                    			allRelevantEndpoints,
                    			consistencyLevel,
                    			clientSigns,
                    			this.ts,
                    			this.clientId,
                    			this.columns);
                    } else if (ByzantineConfig.isErrorLogger) {
                    	logger.error("Resolved data is null");
                    }
                
                    if (ByzantineConfig.isSignaturesLogic)
                    	computeAndSetAllSignatures();

                    return new Row(key, resolved);
            	}
            } 
            
        	resolved = resolveSuperset(versions, timestamp);
        	if (logger.isTraceEnabled())
                logger.trace("versions merged");

            // send updates to any replica that was missing part of the full row
            // (resolved can be null even if versions doesn't have all nulls because of the call to removeDeleted in resolveSuperSet)
            if (resolved != null) {
            	repairResults = scheduleRepairs(resolved, keyspaceName, key, versions, endpoints);
            }
        }
        else
        {
            resolved = replies.get(0).payload.row().cf;
            
            if (ByzantineConfig.isSignaturesLogic) {
            	if (ByzantineTools.isRelevantKeySpace(keyspaceName))
            		computeAndSetAllSignatures();
            }
        }

        if (logger.isTraceEnabled())
            logger.trace("resolve: {} ms.", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start));
        
        return new Row(key, resolved);
    }
	
	private boolean hasBetterValue(ColumnFamily bestKnown, ColumnFamily checked, String column) {
		Cell valCellBestKnown = ByzantineTools.getVallCell(bestKnown, column);
		Cell valCellCecked    = ByzantineTools.getVallCell(checked, column);
		if (valCellCecked == null) {
			return false;
		}
		if (valCellBestKnown == null) {
			return true;
		}
		
		String valueBestKnown = ByzantineTools.getStringFromCell(valCellBestKnown);
		String valueCecked	  = ByzantineTools.getStringFromCell(valCellCecked);
		
		return (valueBestKnown.compareTo(valueCecked) > 0);
	}

    private ColumnFamily byzantineResolver(List<ColumnFamily> versions, DecoratedKey key ){
    	if (ByzantineConfig.isInfoLogger) {
    		logger.info("*** Resolving versions");
    	}
    	
    	// For every version, stores the column numbers it has.
    	List<List<String>> versionsColumns = new LinkedList<List<String>>();

    	// All columns seen in all of the version
    	Set<String> allColumns = new HashSet<String>();
    	
    	CFMetaData cfm = null;
    	for (ColumnFamily version : versions) {
    		if (version == null) {
    			versionsColumns.add(new LinkedList<String>());
    			continue;
    		} else {
    			if (cfm == null) {
    				cfm = version.metadata();
    			}
    		}
    		List<String> columns = ByzantineTools.getColumnsSorted(version, version.metadata());
    		versionsColumns.add(columns);
    		allColumns.addAll(columns);
    		
        	if (ByzantineConfig.isInfoLogger) {
        		logger.info("Version holding: " + Arrays.toString(columns.toArray()));
        	}
    	}
    	
    	if (ByzantineConfig.isInfoLogger) {
    		logger.info("allColumns holding: " + Arrays.toString(allColumns.toArray()));
    	}
    	
    	if (cfm == null) {
    		return null;
    	}
    	
    	ColumnFamily cf = ArrayBackedSortedColumns.factory.create(cfm);
    	Set<Integer> blackList = new HashSet<Integer>();
    	
    	// We find the best version for each value.
    	// If one version is messing with us, it is out.
    	while (!allColumns.isEmpty()) {
    		String column = allColumns.iterator().next();
    		
        	if (ByzantineConfig.isInfoLogger) {
        		logger.info("Solving column: " + column);
        	}
    		
    		long maxTS = Long.MIN_VALUE;
    		ColumnFamily version = null;
    		int selectedVersion = -1;
    		
			for (int i = 0; i < versions.size(); ++i) {
    			ColumnFamily curVersion = versions.get(i);
    			if (blackList.contains(i) || !versionsColumns.get(i).contains(column)) {
    	        	if (ByzantineConfig.isInfoLogger) {
    	        		logger.info("Skiping version: " + i);
    	        	}
    				continue;
    			}
    			
    			Long versionTs = ByzantineTools.getTs(curVersion, column, logger);
    			if (versionTs == null){
	    			if (ByzantineConfig.isErrorLogger) {
	    				logger.error("versionTs == null");
	    			}
	    			continue;
    			}
    			
    			if (versionTs > maxTS || ((versionTs == maxTS) && hasBetterValue(version, curVersion, column))) {
    				maxTS = versionTs;
    				version = curVersion;
    				selectedVersion = i;
    	        	
    				if (ByzantineConfig.isInfoLogger) {
    	        		logger.info("Current best version: " + i + " ts: " + versionTs);
    	        	}
    			}
    		}
    		
    		if (selectedVersion == -1) {
    			allColumns.remove(column);
				if (ByzantineConfig.isInfoLogger) {
	        		logger.error("Can't find good version, skipping column: " + column);
	        	}
    			continue;
    		}
    		
    		Cell valCell = ByzantineTools.getVallCell(version, column);
			Cell metaCell = ByzantineTools.getMetaCell(version, column);
			if (valCell == null || metaCell == null){
				blackList.add(selectedVersion);
				if (ByzantineConfig.isInfoLogger) {
	        		logger.error("valCell == null || metaCell == null: " + column);
	        	}
				continue;
			}
			
			String value = ByzantineTools.getStringFromCell(valCell);
    		MetaVal meta = ByzantineTools.getMetaValFromCell(metaCell);

    		boolean verification = false;
    		
    		// In this case the resolving should not take place here.
    		if (!ByzantineConfig.isMacSignatures) {
    			verification = true;
    		} else {
    			verification = ByzantineTools.verifySignature(
        				meta.clientName, 
        				key, 
        				value, 
        				meta.ts,
        				meta.signautre,
        				logger);
    		}
    		
    		if (verification){
				cf.addColumn(valCell);
				cf.addColumn(metaCell);
				allColumns.remove(column);
				if (ByzantineConfig.isInfoLogger) {
	        		logger.info("Signature verification success, selectedVersion= " + selectedVersion);
	        	}
			} else {
				if (ByzantineConfig.isInfoLogger) {
	        		logger.error("Signature verification failed, selectedVersion= " + selectedVersion);
	        	}
				blackList.add(selectedVersion);
			}
    	}
    	
//    	if (!allColumns.isEmpty()) {
//    		return null;
//    	}
    	
    	return cf;
    }
    
    /**
     * For each row version, compare with resolved (the superset of all row versions);
     * if it is missing anything, send a mutation to the endpoint it come from.
     */
    public static List<AsyncOneResponse> scheduleRepairs(ColumnFamily resolved, String keyspaceName, DecoratedKey key, List<ColumnFamily> versions, List<InetAddress> endpoints)
    {
        List<AsyncOneResponse> results = new ArrayList<AsyncOneResponse>(versions.size());

        for (int i = 0; i < versions.size(); i++)
        {
			ColumnFamily diffCf;
			diffCf = ColumnFamily.diff(versions.get(i), resolved);
			if (diffCf == null) // no repair needs to happen
				continue;
            
            // create and send the mutation message based on the diff
            Mutation mutation = new Mutation(keyspaceName, key.getKey(), diffCf);
            // use a separate verb here because we don't want these to be get the white glove hint-
            // on-timeout behavior that a "real" mutation gets
            Tracing.trace("Sending read-repair-mutation to {}", endpoints.get(i));
            results.add(MessagingService.instance().sendRR(mutation.createMessage(MessagingService.Verb.READ_REPAIR),
                    									   endpoints.get(i)));
        }

        return results;
    }
    
    /**
     * For each row version, compare with resolved (the superset of all row versions);
     * if it is missing anything, send a mutation to the endpoint it come from.
     */
    public static AsyncAllResponses byzantineScheduleRepairs(
    		ColumnFamily resolved, 
    		String keyspaceName, 
    		DecoratedKey key, 
    		List<InetAddress> endpoints, 
    		String clientSign,
    		List<InetAddress> allRelevantEndpoints,
    		ConsistencyLevel consistencyLevel,
    		List<String> clientSigns,
    		String ts,
    		String clientId,
    		String columns)
    {
    	// Will hold all target nodes for repair
    	List<InetAddress> repairTargets;
    	
    	if (ByzantineConfig.isDataPathLogic) {
	    	// Targeting all those who didn't respond (N minus R)
    		repairTargets = new LinkedList<InetAddress>(allRelevantEndpoints);
  	
	    	// Removing those who we have versions of (will be checked)
	    	repairTargets.removeAll(endpoints);
    	} else {
    		// Will target only those we responded and requires an update
    		repairTargets = new LinkedList<InetAddress>();
    	}

    	int updatedreplicas = 0;
       	// Adding all those who responded with old data
    	for (int i = 0; i < clientSigns.size(); ++i)
        {
    		if (clientSign.equals(clientSigns.get(i))) {
    			updatedreplicas++;
    		} else {
    			repairTargets.add(endpoints.get(i));
    		}
        }
    	
    	int blockFor = 0;
    	if (ByzantineConfig.isDataPathLogic) {
    		blockFor = consistencyLevel.blockFor(Keyspace.open(keyspaceName));
    		blockFor -= updatedreplicas;
    	} else {
    		blockFor = repairTargets.size();
    	}
    	
    	if (ByzantineConfig.isInfoLogger) {
        	int totalAliveNode  = -1;
        	if (ByzantineConfig.isDataPathLogic) {
        		totalAliveNode = allRelevantEndpoints.size();
        	}
    		logger.info(
    			"[ronili] - Total alive nodes {} total versions {} updated replicas {}", 
    			totalAliveNode , endpoints.size(), updatedreplicas);
    		logger.info(
    			"[ronili] - Configure WriteBack handler, waiting for {} nodes from requested {}", 
    			blockFor, repairTargets.size());
    	}
    	
    	String hvals = ByzantineTools.computeHashOnMessageValues(logger, resolved, columns);
    	AsyncAllResponses handler = 
    			new AsyncAllResponses(
    					clientSign, 
    					keyspaceName, 
    					blockFor, 
    					repairTargets.size(), 
    					ByzantineTools.getKey(key),
    					ts,
    					hvals);   	
    	
    	for (InetAddress target : repairTargets) {
    		if (ByzantineConfig.isInfoLogger) 
    			logger.info("[ronili] Sending read-repair-mutation to {}", target);
    		
        	Mutation mutation = new Mutation(keyspaceName, key.getKey(), resolved.cloneMe());
        	mutation.isByzReadReapir = true;
        	mutation.ts = ts;
        	mutation.clientId = clientId;
        	mutation.columns = columns;
        	
    		MessagingService.instance().sendRR(
    				mutation.createMessage(MessagingService.Verb.READ_REPAIR),
    				target,
    				handler
    				);
    	}

        return handler;
    }


    static ColumnFamily resolveSuperset(Iterable<ColumnFamily> versions, long now)
    {
        assert Iterables.size(versions) > 0;

        ColumnFamily resolved = null;
        for (ColumnFamily cf : versions)
        {
            if (cf == null)
                continue;

            if (resolved == null)
                resolved = cf.cloneMeShallow();
            else
                resolved.delete(cf);
        }
        if (resolved == null)
            return null;

        // mimic the collectCollatedColumn + removeDeleted path that getColumnFamily takes.
        // this will handle removing columns and subcolumns that are suppressed by a row or
        // supercolumn tombstone.
        QueryFilter filter = new QueryFilter(null, resolved.metadata().cfName, new IdentityQueryFilter(), now);
        List<CloseableIterator<Cell>> iters = new ArrayList<>(Iterables.size(versions));
        for (ColumnFamily version : versions)
            if (version != null)
                iters.add(FBUtilities.closeableIterator(version.iterator()));
        filter.collateColumns(resolved, iters, Integer.MIN_VALUE);
        return ColumnFamilyStore.removeDeleted(resolved, Integer.MIN_VALUE);
    }

    public Row getData()
    {
        assert !replies.isEmpty();
        
        if (ByzantineConfig.isSignaturesLogic) {
        	if (ByzantineTools.isRelevantKeySpace(keyspaceName)){
        		computeAndSetAllSignatures();
        	}
        }
        
        return replies.get(0).payload.row();
    }

    public boolean isDataPresent()
    {
        return !replies.isEmpty();
    }

    public int getMaxLiveCount()
    {
        return maxLiveCount;
    }
}
