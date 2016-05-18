package cs.technion;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.cassandra.config.CFMetaData;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.Schema;
import org.apache.cassandra.cql3.ColumnIdentifier;
import org.apache.cassandra.db.ArrayBackedSortedColumns;
import org.apache.cassandra.db.Cell;
import org.apache.cassandra.db.BufferCell;
import org.apache.cassandra.db.ColumnFamily;
import org.apache.cassandra.db.DecoratedKey;
import org.apache.cassandra.db.Keyspace;
import org.apache.cassandra.db.Mutation;
import org.apache.cassandra.db.ReadCommand;
import org.apache.cassandra.db.ReadResponse;
import org.apache.cassandra.db.Row;
import org.apache.cassandra.db.WriteResponse;
import org.apache.cassandra.db.composites.CellName;
import org.apache.cassandra.db.composites.CellNames;
import org.apache.cassandra.net.MessageIn;
import org.apache.cassandra.service.AbstractReadExecutor;
import org.apache.cassandra.service.DigestMismatchException;
import org.apache.cassandra.service.StorageProxy;
import org.apache.cassandra.service.StorageService;
import org.apache.cassandra.utils.FBUtilities;
import org.apache.cassandra.utils.Pair;
import org.slf4j.Logger;

public class ByzantineTools {

	public static final String KEYSPACE = "demo";
	public static final String TABLE = "tbl7";
	public static final String KEY_COLUMN   = "key_1";
	public static final String VALUE_COLUMN_PREFIX = "val_";
	public static final String META_COLUMN_PREFIX  = "meta_";
	public static final String NODES_SIGNATURES_COLUMN = "signatures";
	public static final String EMPTY_MESSAGE = "E";
	public static final String WRITE_BACK_MESSAGE = "WB";
	public static final String RESOLVED_PREFIX = "R#";
	public static final String REQUEST_ALL_FIELDS = "*";
	
	private static final String SIGN_WITH_TS_PATTERN = "%s:%s:%s:%s";
	private static final Encryption encryption = initAndGetEncryptionInstace();
	
	private static String NODE_NAME = null;
	
	public static class MetaVal{
		public String clientName;
		public String signautre;
		public String ts;
		
		MetaVal(String ts, String clientName, String signature) {
			this.ts = ts;
			this.clientName = clientName;
			this.signautre = signature;
		}
	}
	
	public static class KeyMetaData{
		public String key;
		public String ts;
		public String clientId;
		public String valNums;
		public List<String> blackList;
		
		public KeyMetaData(String key, String ts, String valNums, String clientId, String blackList) {
			this.key = key;
			this.ts = ts;
			this.valNums = valNums;
			
			if (clientId != null) {
				this.clientId = clientId;
			}
			
			if (blackList != null) {
				this.blackList = new LinkedList<String>();
				for (String node : blackList.split(":")) {
					this.blackList.add(node);
				}
			}
		}
	}
	
	// Expected key:ts:val_nums:clientName:blacklist
	public static KeyMetaData parseInjectedKey(String keyString){
		String[] splitted = keyString.split(";");

		if (splitted.length == 5){
			return new KeyMetaData(splitted[0], splitted[1], splitted[2], splitted[3], splitted[4]);
		}
		
		if (splitted.length == 4){
			return new KeyMetaData(splitted[0], splitted[1], splitted[2], splitted[3], null);
		}
		
		if (splitted.length == 3){
			return new KeyMetaData(splitted[0], splitted[1], splitted[2], null, null);
		}
		
		return null;
	}
	
	public static String injectKeyData(String key, String ts, String clientName, String blackList) {
		String injectedString = key + ";" + ts;
		
		if (clientName != null) {
			injectedString += ";" + clientName;
			
			if (blackList != null) {
				injectedString += ";" + blackList;
			}
		}
		
		return injectedString;
	}
		
	// str = TS:clientName:Sign
	public static MetaVal parseString(String str){
		int delimiterLoc = str.indexOf(":");
		if (delimiterLoc == -1) {
			return null;
		}
		
		String ts = str.substring(0, delimiterLoc);
		String rest = str.substring(delimiterLoc+1);
		
		delimiterLoc = rest.indexOf(":");
		if (delimiterLoc == -1) {
			return null;
		}
		
		String clientName = rest.substring(0, delimiterLoc);
		String sign = rest.substring(delimiterLoc+1);
		
		return new ByzantineTools.MetaVal(ts, clientName, sign);
	}
	
	public static String createMetaString(String ts, String clientName, String signature) {
		return String.format("%s:%s:%s", ts, clientName, signature);
	}
	
    public static Encryption getEncryptionInstance(){
        return encryption;
    }
		
	public static Encryption initAndGetEncryptionInstace() {
		Encryption enc = Encryption.getInstance();
		if (enc.isInit() == false) {
			try {
				enc.init(getNodePrivateKeyPath().toString() , getNodeName(), getKeystorePass());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return enc;
	}
	
	public static String getKeystorePass(){
		String keystorePass = DatabaseDescriptor.getServerEncryptionOptions().keystore_password;
		return keystorePass;
	}
	
	public static Path getNodePrivateKeyPath(){
		String keyStorePath = DatabaseDescriptor.getServerEncryptionOptions().keystore;
		keyStorePath += ByzantineConfig.SIGNATURES_SUFFIX;
		Path path = Paths.get(keyStorePath);
		return path;
	}
	
	public static String getNodeName() {
		if (NODE_NAME == null) {
			String keyStoreFile = getNodePrivateKeyPath().getFileName().toString();
			String[] splitted = keyStoreFile.split("-");
			if (splitted == null || splitted.length <= 0) {
				NODE_NAME = "default";
			} else {
				NODE_NAME = splitted[0];
			}
		}
		return NODE_NAME;
	}
	
	public static String safeConcat(String left, String right) {
		if (left == null || left.isEmpty()) {
			return right;
		} else {
			return left + "," + right;
		}
	}
	
	// Gets pairs of <clientSign, nodeSign>
	public static String assembleSignaturesStringPairs(
			String clientSign, 
			Collection<Pair<String,String>> signaturesCol ) {

		String signatures = "";
		for (Pair<String, String> p : signaturesCol) {
			if (p.left.equals(clientSign)) {
				signatures = safeConcat(signatures, p.right);
			}
		}
		return signatures;
	}
	
	// Gets signatures and a base string
	public static String assembleSignaturesString(
			String signatures,
			Collection<String> wbSignatures) {
		if (wbSignatures != null) {
			for (String wbSign : wbSignatures) {
				signatures = safeConcat(signatures, wbSign);
			}
		}
		return signatures;
	}
	
	// Checks if keyspace is relevant.
	public static boolean isRelevantKeySpace(String ks){
		return ks.equals(KEYSPACE);
	}
	
	// Checks if keyspace is relevant.
	public static boolean isRelevantKeySpace(Keyspace ks){
		if (ks == null) {
			return false;
		}
		return ks.getName().equals(KEYSPACE);
	}
	
	public static Row buildSignaturesRow(String ksName, String signatures, ByteBuffer key) {
		CFMetaData cfm = Schema.instance.getCFMetaData(ksName,ByzantineTools.TABLE);
		ColumnFamily cf = ArrayBackedSortedColumns.factory.create(cfm);
		ColumnIdentifier ci = new ColumnIdentifier(ByzantineTools.NODES_SIGNATURES_COLUMN, true);
		CellName cellName = CellNames.simpleSparse(ci);
		// Timestamp is set to 0.
		Cell cell = new BufferCell(cellName, ByteBuffer.wrap(signatures.getBytes()));
		cf.addColumn(cell);
		return new Row(key, cf);
	}
	
	// Return value of the column in the mutation
	public static String getData(Mutation mutation, String column, Logger logger){
    	// Getting our metadata from the row.
    	for (ColumnFamily cf : mutation.getColumnFamilies()) {
    		String val = getData(cf,column);
    		
    		if (val != null) {
    			return val;
    		}
    	}
    	
    	return null;
	}
	
	// Return the key value from the mutation
	public static String getKeyData(Mutation m){
		return getKeyData(m.key());
	}
	
	// Return the key value from the mutation
	public static String getKeyData(ByteBuffer b){
		ByteBuffer bb = b.duplicate();
		final byte[] bytes = new byte[bb.remaining()];
		bb.get(bytes);
		return new String(bytes);
	}
	
	// Return value of the column in the row
	public static String getData(ColumnFamily cf, String column){
		return new String(getDataBytes(cf, column));
	}
		
	// Return value of the column in the row
	public static byte[] getDataBytes(ColumnFamily cf, String column){
		if (cf == null){
			return null;
		}
		
		CFMetaData cfm = Schema.instance.getCFMetaData(cf.id());
		if (cfm == null) {
			return null;
		}
	
		for (Cell c : cf.getSortedColumns()) {
			String name = c.name().cql3ColumnName(cfm).toString();
			//logger.error("Name: " + name);
			
			if (name.equals(column)) {
				ByteBuffer bb = c.value().duplicate();
    			final byte[] bytes = new byte[bb.remaining()];
    			bb.get(bytes);
				return bytes;
			}
		}
    	
    	return null;
	}
	
	// @Nullable
	// Returns the client signature for the row. 
	public static String getSignature(Row row, Logger logger) {	
		if (row == null) {
			return null;
		}
		
		return getData(row.cf, NODES_SIGNATURES_COLUMN);
	}
	
//	// Given a row, checks the signature and if it is correct, injects a new signature
//	// in the signatures column
//	@Deprecated
//	public static void injectSignature(String keyspace, Row row, Logger logger, String ts, String clientId){
//		// Check if is "our" keyspace
//		if (!isRelevantKeySpace(keyspace) || row == null) {
//			return;
//		}
//		
//		ColumnFamily cf = row.cf;
//		if (cf == null) {
//			return;
//		}
//		
//		CFMetaData cfm = Schema.instance.getCFMetaData(cf.id());
//		if (cfm == null) {
//			return;
//		}
//		
//		String extentedSign = computeNodeSignature(row,logger,ts,clientId).right; 
//		if (extentedSign == null) {
//			return;
//		}
//		
//		injectGivenSignature(extentedSign, cf, cfm, logger);
//	}
	
	public static void injectGivenSignature(String signatures ,Row row, Logger logger){
		// Inject the extentedSign in the right cell
		injectGivenSignature(signatures, row.cf, logger);
	}
	
	public static void injectGivenSignature(String signatures ,Row row, CFMetaData cfm, Logger logger){
		injectGivenSignature(signatures, row.cf, cfm, logger);
	}
	
	public static void injectGivenSignature(String signatures ,ColumnFamily cf, Logger logger){
		if (cf == null)
			return;
		CFMetaData cfm = Schema.instance.getCFMetaData(cf.id());
		injectGivenSignature(signatures, cf, cfm, logger);
	}

	// Injects the signatures string to the NODES_SIGNATURES_COLUMN column in the cf
	public static void injectGivenSignature(String signatures ,ColumnFamily cf, CFMetaData cfm, Logger logger){
		if (signatures == null || cf == null || cfm == null) 
			return;
		
		// Inject the extentedSign in the right cell
		for (Cell c : cf.getSortedColumns()) {
			String name = c.name().cql3ColumnName(cfm).toString();
			if (name.equals(NODES_SIGNATURES_COLUMN)) {
				
//				if (logger != null)
//					logger.error("[ronili] injected signatures in response: " +  signatures);
				// We use out costume buffer implementation
				BufferCell bufferC = (BufferCell)c;
				bufferC.setValue(ByteBuffer.wrap(signatures.getBytes()));
				return;
			}
		}
		
		if (ByzantineConfig.isInfoLogger) {
			if (logger != null)
				logger.info("[ronili] Couldn't find the column "+ NODES_SIGNATURES_COLUMN + 
						" for signature injection. Adding it.");
		}
		
		ColumnIdentifier ci = new ColumnIdentifier(ByzantineTools.NODES_SIGNATURES_COLUMN, true);
		CellName cellName = CellNames.simpleSparse(ci);
		// Timestamp is set to 0.
		Cell cell = new BufferCell(cellName, ByteBuffer.wrap(signatures.getBytes()));
		cf.addColumn(cell);
	}
	
	// Current implementation return current time
	static private Long getFreshTs() {
		return System.currentTimeMillis();
	}
	
	// return (NODE_NAME:NodeSign(base:FreshTS):FreshTS)
	public static String computeEmptySignature(String key, Logger logger, String ts, String clientId) {
		return computeNodeSignature(key, EMPTY_MESSAGE, logger, ts ,clientId);
	}
	
	
	// return (NODE_NAME:NodeSign(KEY:EMPTY_MESSAGE:FreshTS):FreshTS)
	public static String computeNodeSignature(String key, String base, Logger logger, String ts, String clientId) {
		// Get time stamp
		if (ts == null){
			logger.error("No ts supplied for computeNodeSignature");
			return null;
		}

		// Sign on 'EMPTY_MESSAGE:freshTs'
		byte[] nodeSign = null;
		try 
		{
			byte[] data = String.format(SIGN_WITH_TS_PATTERN, 
					key,
					"",
					base, 
					ts)
					.getBytes();
			
			if (ByzantineConfig.isInfoLogger)
				logger.info("signing on empty data: ", key + ts);
			
			if (ByzantineConfig.isMacSignatures){
				//TODO get clientName as paramter
				nodeSign = encryption.signDataSym(data, "clien1", getNodeName());
			} else {
				nodeSign = encryption.signData(data);
			}
			
			//logger.error("nodeSign: " + new String(nodeSign));
		}
		catch (Exception e)
		{
			if (ByzantineConfig.isErrorLogger)
				logger.error("Error in signer {}", e.getMessage());
			return null;
		}
		
		// Build the signature with meta: NodeName:clientSign:freshTs
		String extentedSign = 
				String.format("%s:%s",
						getNodeName(),
						new String(nodeSign));
		
		//logger.error("computeNodeSignature extentedSign: " + extentedSign);
		return extentedSign;
	}
	
	public static class NodeSignature {
		public String clientSign;
		public String extenedNodeSign;
		public String hvals;
	}
	
	// TODO: merge with String computeNodeSignature
	// return NodeSignature of clientSign and (NODE_NAME:NodeSign(ClientSign:ts)) and hvals
	public static NodeSignature computeNodeSignature(Row row, Logger logger, String ts, String clientId, String requestedColumns) {
		if (row == null){
			return null;
		}
		
		ColumnFamily cf = row.cf;
		if (cf == null) {
			return null;
		}
		
		CFMetaData cfm = Schema.instance.getCFMetaData(cf.id());
		if (cfm == null) {
			return null;
		}
		
		// Get time stamp
		if (ts == null) {
			logger.error("No ts supplied for computeNodeSignature");
			return null;
		}
		
		boolean requestedAllValus = requestedColumns.equals(REQUEST_ALL_FIELDS);
		Set<String> requested = null;
		if (!requestedAllValus){
			requested = new HashSet<String>();
			for (String i : requestedColumns.split(":")) {
				requested.add(i);
			}
		}
		
		// Get client signature and value
		// Currently supports up to 10 valus table
		int collectedColumns = 0;
		String sign = "";
		String vals = "";
		for (Cell c : cf.getSortedColumns()) {
			String name = c.name().cql3ColumnName(cfm).toString();

			if (name.isEmpty()) continue;
			
			if (!requestedAllValus) {
				String last = name.substring(name.length() - 1);
				if (!requested.contains(last)) continue;
			}
			
			if (name.startsWith(META_COLUMN_PREFIX)) {
    			String metaString = getString(c.value());
    			sign += parseString(metaString).signautre;
    			collectedColumns++;
			} else if (name.startsWith(VALUE_COLUMN_PREFIX)) {
				String value = getString(c.value());
				vals += value;
				
				if (ByzantineConfig.isInfoLogger)
					logger.info("add val" + name);
			}
		}
		
		if (collectedColumns == 0) {
			sign = null;
		}
		
		if (sign == null){
        	if (ByzantineConfig.isErrorLogger)
        		logger.error("can't find client signature");
			return null;
		}
		
		String hvals = "";
		if (!vals.isEmpty()) {
			hvals = computeCassandraHash(logger, vals);
		}
		
		String key = getKey(row.key);
		String clientSign = sign;
		
		// Sign on 'clientSign:freshTs'
		byte[] nodeSign = null;
		try 
		{
			byte[] data = String.format(SIGN_WITH_TS_PATTERN, 
									key,
									hvals,
									clientSign, 
									ts)
									.getBytes();
			
			if (ByzantineConfig.isMacSignatures){
				nodeSign = encryption.signDataSym(data, clientId, getNodeName());
			} else {
				nodeSign = encryption.signData(data);
			}
			//logger.error("nodeSign: " + new String(nodeSign));
		}
		catch (Exception e)
		{
			if (ByzantineConfig.isErrorLogger)
				logger.error("Error in signer {}", e.getMessage());
			return null;
		}
		
		if (nodeSign == null) {
			if (ByzantineConfig.isErrorLogger)
				logger.error("signature failed");
			return null;
		}
		
		// Build the signature with meta: (NODE_NAME:NodeSign(ClientSign:ts))
		String extentedSign = 
				String.format("%s:%s",
						getNodeName(),
						new String(nodeSign)
						);
		
		if (ByzantineConfig.isInfoLogger)
			logger.info("computeNodeSignature NODE_NAME:" + getNodeName() + " ts: " + ts);
		
		NodeSignature result = new NodeSignature();
		result.clientSign = clientSign;
		result.extenedNodeSign = extentedSign;
		result.hvals = hvals;
		
		return result;
	}
	
	public static String getNonValidReadSign() {
		return String.format("%s:%s",
						getNodeName(),
						 "non-valid sign"
						);
	}
	
	// Aux for checkMutationSignatureAux : read comments there.
	// If signature pass, returns NodeSign(ClientSign)
	public static byte[] checkMutationSignature(Mutation mutation, final Logger logger, String symmetricSign) {
		String symSignForThis = getThisNodeSign(symmetricSign);
		
		if (symSignForThis != null) {
			byte[] sign = checkMutationSymmetricSignature(mutation, logger, symSignForThis);
			if (sign != null) {
				return sign;
			}
			
			if (ByzantineConfig.isErrorLogger)
				logger.error("Failed symmetric verification, falling back to public signature");
		}
		
		return checkMutationSignatureAux(mutation, logger, false, "0", null, false, null);
		
	}

	private static byte[] checkMutationSymmetricSignature(Mutation mutation,
			Logger logger, String symmetricSign) {
		
		// Checking only our keyspace mutations
		if (!isRelevantKeySpace(mutation.getKeyspaceName())) {
			return "00".getBytes();
		}
		
		String key1 = new String(mutation.key().duplicate().array());
		if (ByzantineConfig.isInfoLogger)
			logger.info("[Roni] Checking symmetric signature for key: " + key1);
    	    	
    	if (mutation.getColumnFamilies().size() != 1) {
    		if (ByzantineConfig.isErrorLogger)
    			logger.error("[Roni] Gotm ore than 1 cf. there are: " + mutation.getColumnFamilies().size());
    		return null;
    	}
    	ColumnFamily cf = mutation.getColumnFamilies().iterator().next();
    	
    	CFMetaData cfm = Schema.instance.getCFMetaData(cf.id());
		List<String> columns = getColumnsSorted(cf, cfm);
		if (columns == null) {
			if (ByzantineConfig.isErrorLogger)
				logger.error("columns");
			return null;
		}
		
		String allVals = "";
		String allMetas = "";
		String allSigns = "";
		String clientName = null;
		
    	for (Cell c : cf.getSortedColumns()) {
			String name = c.name().cql3ColumnName(cfm).toString();
			if (name.startsWith(META_COLUMN_PREFIX)) {
    			String meta = getStringFromCell(c);
    			allMetas += meta;
    			
    			MetaVal metaVal = parseString(meta);
    			clientName 	= metaVal.clientName;
    			allSigns   += metaVal.signautre;
    			
			} else if (name.startsWith(VALUE_COLUMN_PREFIX)) {
				String value = getStringFromCell(c);
				allVals += value;
			} 
		}
	    
    	String signedData = key1 + allVals + allMetas;
			
    	try {
			if (!encryption.verifySymData(signedData.getBytes(), symmetricSign.getBytes(), clientName, getNodeName())) {
				if (ByzantineConfig.isErrorLogger) {
					logger.error("verify symmetric sign failed for {} {} {} {} ", key1, allVals, allMetas, symmetricSign);
				}
				return null;
			}
		} catch (Exception e) {
			if (ByzantineConfig.isErrorLogger)
				logger.error("Verifier failed {}" ,e.getMessage());
		}
	    	
		byte[] dataToSignOn = allSigns.getBytes();
		
		byte[] nodeSign = null;
		try {
			if (ByzantineConfig.isMacSignatures){
				if (ByzantineConfig.isInfoLogger)
					logger.info("signing with {}-{} ", clientName, getNodeName());
				nodeSign = encryption.signDataSym(dataToSignOn, clientName, getNodeName());
			} else {
				nodeSign = encryption.signData(dataToSignOn);
			}
		} catch (Exception e) {
			if (ByzantineConfig.isErrorLogger)
				logger.error("Error in signer {}", e.getMessage());
			return null;
		}
		
		if (ByzantineConfig.isInfoLogger)
			logger.info("New signature: ", new String(nodeSign));
		
		return nodeSign;
	}

	// Aux for checkMutationSignatureWithTS : read comments there.
	// If signature pass, returns (WRITE_BACK:NODE_NAME:NodeSign(WRITE_BACK:ClientSign:TS))
	public static String checkMutationSignatureWithTSAndWB(Mutation mutation, final Logger logger, String ts, String clientId, String columns) {
		byte[] sign = checkMutationSignatureAux(mutation, logger, true, ts, clientId, true, columns);
		
		if (sign == null) {
			return null;
		}
		
		return 
				String.format("%s:%s:%s",
						WRITE_BACK_MESSAGE,
						getNodeName(),
						new String(sign)
						);
	}
	
	// Aux for checkMutationSignatureAux : read comments there.
	// If signature pass, returns (NODE_NAME:NodeSign(ClientSign:FreshTS):FreshTS)
	public static String checkMutationSignatureWithTS(Mutation mutation, final Logger logger, String ts, String clientId) {
		byte[] sign = checkMutationSignatureAux(mutation, logger, true, ts, clientId, false, null);
		
		if (sign == null) {
			return null;
		}
		
		return 
				String.format("%s:%s:%s",
						getNodeName(),
						new String(sign),
						ts
						);
	}
	
	public static Long getTs(ColumnFamily cf, String column, Logger logger) {
		if (cf == null) {
			if (ByzantineConfig.isErrorLogger) {
				logger.error("cf == null");
			}
			return null;
		}
		
		Cell c = getVallCell(cf, column);
		if (c == null) {
			if (ByzantineConfig.isErrorLogger) {
				logger.error("getMetaCell == null");
			}
			return null;
		}
		
		return c.timestamp();
	}
	
	public static List<String> getColumnsSorted(ColumnFamily cf, CFMetaData cfm) {
		List<String> columns = new LinkedList<String>();
		for (Cell c : cf.getSortedColumns()) {
			String name = c.name().cql3ColumnName(cfm).toString();
			if (name.startsWith(VALUE_COLUMN_PREFIX)) {
				name = name.replaceAll(VALUE_COLUMN_PREFIX, "");
				columns.add(name);
			}
		}
		
		if (columns.isEmpty()) {
			return columns;
		}
		
		Collections.sort(columns, new Comparator<String>() {
			@Override
			public int compare(String s1, String s2) {
				Integer i1 = Integer.parseInt(s1);
				Integer i2 = Integer.parseInt(s2);
				return i1.compareTo(i2);
			}
		});
		
		return columns;
	}
	
	
	// Check if a the signature on the data is correct.
	// Gets CF
	// returns clientSign if pass, otherwise null
	static private Pair<String, byte[]> innerCheckColumnFamilySignature(
				ColumnFamily cf,
				String key,
				final Logger logger) {
		
		CFMetaData cfm = Schema.instance.getCFMetaData(cf.id());
		List<String> columns = getColumnsSorted(cf, cfm);
		if (columns == null) {
			if (ByzantineConfig.isErrorLogger)
				logger.error("columns");
			return null;
		}
		
		String sampledClientName = null;
		String allSigns = "";
		for (String column : columns) {
			String sign = null;
	    	String value = null;
	    	String clientName = null;
	    	String ts = null;
	    	
	    	for (Cell c : cf.getSortedColumns()) {
				String name = c.name().cql3ColumnName(cfm).toString();
				if (name.equals(META_COLUMN_PREFIX + column)) {
	    			MetaVal meta = getMetaValFromCell(c);
					sign = meta.signautre;
					clientName = meta.clientName;
				} else if (name.equals(VALUE_COLUMN_PREFIX + column)) {
					value = getString(c.value());
					ts = Long.toString(c.timestamp());
				} 
			}
	    	
			if (sign == null || value == null || ts == null || clientName == null) {
				if (ByzantineConfig.isErrorLogger)
					logger.error("some input is null for column# " + column);
	    		return null;
	    	}
	    	
			if (ByzantineConfig.isInfoLogger)
				logger.info("Verifying signature on: {} {} {}", key, value, ts);
			
	    	try {
				if (!encryption.verifyData(clientName, (key + value + ts).getBytes(), sign.getBytes())) {
					if (ByzantineConfig.isErrorLogger) {
						logger.error("verifyData failed for column# " + column);
						logger.error("{} {} {} {} ", clientName, key, value, ts, sign);
					}
					return null;
				}
			} catch (Exception e) {
				if (ByzantineConfig.isErrorLogger)
					logger.error("Verifier failed {}" ,e.getMessage());
			}
	    	
	    	sampledClientName = clientName;
	    	allSigns += sign;
		}

		return Pair.create(sampledClientName, allSigns.getBytes());
	}
	
	// Check if a the signature on the data is correct.
	// Gets row
	// returns True\False
	public static boolean checkColumnFamilySignature(
			Row row,
			final Logger logger) {
		return checkColumnFamilySignature(row.cf, row.key, logger);
	}
	
	public static String getString(ByteBuffer buffer) {
		ByteBuffer bb = buffer.duplicate();
		final byte[] bbBytes = new byte[bb.remaining()];
		bb.get(bbBytes);
		
		return new String(bbBytes);
	}
	
	public static String getKey(DecoratedKey dKey){
		return getString(dKey.getKey());
	}
	
	// Check if a the signature on the data is correct.
	// Gets CF
	// returns True\False
	public static boolean checkColumnFamilySignature(
			ColumnFamily cf,
			DecoratedKey dKey,
			final Logger logger) {
	
		if (cf == null) {
			return false;
		}

		String key = getKey(dKey);
		
    	if (innerCheckColumnFamilySignature(cf, key, logger) != null) {
    		return true;
    	}
    	
    	return false;
	}
	
	// Check if a the signature on the data is correct.
	// Gets mutation and given_ts (if include_ts == true)
	// The mutation has signer, value, ts, signature
	// Signs (signature:given_ts) (if include_ts == true)
	// Signs (signature) (if include_ts == false)
	// returns signature
	public static byte[] checkMutationSignatureAux(
			Mutation mutation, 
			final Logger logger, 
			boolean includeTs,
			String ts,
			String clientName,
			boolean isWriteBack,
			String columns) {

		// Checking only our keyspace mutations
		if (!isRelevantKeySpace(mutation.getKeyspaceName())) {
			return "00".getBytes();
		}
		
		String key1 = new String(mutation.key().duplicate().array());
		if (ByzantineConfig.isInfoLogger)
			logger.info("[Roni] Checking signature for key: " + key1);
    	    	
    	if (mutation.getColumnFamilies().size() != 1) {
    		if (ByzantineConfig.isErrorLogger)
    			logger.error("[Roni] Got ore than 1 cf. there are: " + mutation.getColumnFamilies().size());
    		return null;
    	}
    	ColumnFamily cf = mutation.getColumnFamilies().iterator().next();
    	
    	Pair<String, byte[]> innerCheck = innerCheckColumnFamilySignature(cf, key1, logger);
    	if (innerCheck == null) {
    		if (ByzantineConfig.isErrorLogger)
				logger.error("innerCheck == null");
    		return null;
    	}
    	
    	if (!includeTs){
    		clientName = innerCheck.left;
    	}
		byte[] clientSign = innerCheck.right;
		if (clientSign == null) {
    		if (ByzantineConfig.isErrorLogger)
				logger.error("clientSign == null");
			return null;
		}
		
		byte[] data;
		if (includeTs) {
			if (isWriteBack) {
				String hvals;
				if (cf == null) {
					hvals = "";
				} else {
					hvals = computeHashOnMessageValues(logger, cf, columns);
				}
				String relevantClientSign = getRelevantClientSign(logger, cf, columns);
				data = String.format("%s:%s:%s:%s", 
						key1,
						hvals,
						relevantClientSign, 
						ts)
						.getBytes();
			} else {
				data = String.format("%s:%s:%s", 
								key1,
								new String(clientSign), 
								ts)
								.getBytes();
			}
		} else {
			data = clientSign;
		}
		
		if (isWriteBack) {
			data = (WRITE_BACK_MESSAGE + ":" + new String(data)).getBytes();
		}
		
		if (ByzantineConfig.isInfoLogger)
			logger.info("signing on data for key " + key1);
		
		byte[] nodeSign = null;
		try {
			if (ByzantineConfig.isMacSignatures){
				if (ByzantineConfig.isInfoLogger)
					logger.info("signing with {}-{} ", clientName, getNodeName());
				nodeSign = encryption.signDataSym(data, clientName, getNodeName());
			} else {
				nodeSign = encryption.signData(data);
			}
		} catch (Exception e) {
			if (ByzantineConfig.isErrorLogger)
				logger.error("Error in signer {}", e.getMessage());
			return null;
		}
		
		if (ByzantineConfig.isInfoLogger)
			logger.info("New signature: ", new String(nodeSign));
		
		return nodeSign;
	}

	// Gets the client signatures sorted
	public static String getClientSigns(ColumnFamily cf) {
		if (cf == null) {
			return null;
		}
		
		CFMetaData cfm = Schema.instance.getCFMetaData(cf.id());
		List<String> columns = getColumnsSorted(cf, cfm);
		if (columns == null) {
			return null;
		}
		
		String allSigns = "";
		for (String column : columns) {
			Cell c = getMetaCell(cf, column);			
			if (c == null) {
				return null;
			}
			
			MetaVal meta = getMetaValFromCell(c);
			if (meta == null) {
				return null;
			}
	    	
	    	allSigns += meta.signautre;
		}

		return allSigns;
	}
	
	// Gets the data in the CLIENT_SIGNATURE_COLUMN colum
//	public static String getClientSign(ColumnFamily cf) {
//		byte[] metaBytes = getDataBytes(cf, META_COLUMN);
//		MetaVal meta = parseString(new String(metaBytes));
//		String sign = meta.signautre;
//		return sign;
//	}
	
//	// Gets the data in the CLIENT_SIGNATURE_COLUMN colum
//	public static byte[] getClientSignBytes(ColumnFamily cf) {
//		return getClientSign(cf).getBytes();
//	}
	
    // Wrapper for isMessageVerifiedAux
    // Adds keySpace check and takes data from ReadResponse message (nodeSign) 
	// Assume relevant keyspace
    public static <TMessage> boolean isReadResponseMessageVerified(
    		MessageIn<TMessage> message,
    		ByteBuffer key,
    		Logger logger,
    		String ts){ 
    	
		ReadResponse result = (ReadResponse)message.payload;
		String clientSign = result.clientSign;
		String nodeSign = result.signature;	
		String hvals = result.hash;
		
    	return isMessageVerifiedAux(message.from.toString(), new String(key.duplicate().array()), logger, clientSign, nodeSign, ts, false, hvals);
    }
    
    // Assume relevant keyspace
    public static <TMessage> void computeAndInjectCassandraHashIfNecessary(MessageIn<TMessage> message, Logger logger, String columns) {
    	ReadResponse result = (ReadResponse)message.payload;
    	if (!result.isDigestQuery()) {
			if (result.row().cf == null) {
				// Empty
				result.hash = "";
			} else {
				result.hash = computeHashOnMessageValues(logger, result.row().cf, columns);
				if (ByzantineConfig.isInfoLogger) {
					logger.info("Computed hash on data: " + result.hash);
				}
			}
		}
    }


	// Wrapper for isMessageVerifiedAux
    // Adds keySpace check and takes data from WriteResponse message (nodeSign) 
    public static <TMessage> boolean isMessageVerifiedWriteBack(
    		MessageIn<TMessage> message,
    		String key,
    		Logger logger,
    		String keyKeyspace,
    		String clientSignIn,
    		String ts,
    		String hvals){
   
    	if (!isRelevantKeySpace(keyKeyspace)){
    		return true;
    	}
    	
    	WriteResponse result = (WriteResponse)message.payload;
    	String nodeSign = result.signature;
    	
    	return isMessageVerifiedAux(message.from.toString(), key, logger, clientSignIn, nodeSign, ts, true, hvals);
    }
    
    // Assume relevant keyspace
    public static <TMessage> boolean isEmptyData(MessageIn<TMessage> message){
		ReadResponse result = (ReadResponse)message.payload;
		String clientSign = result.clientSign;
		
		if (clientSign == null || clientSign.isEmpty()) {
			return true;
		}
		
    	return false;
    }
    
    // wrapper
    public static <TMessage> boolean isMessageVerifiedAux(
    		String from,
    		DecoratedKey keyD,
    		Logger logger,
    		String clientSign, 
    		String nodeSign,
    		String ts){
    	return isMessageVerifiedAux(from, getKey(keyD), logger, clientSign, nodeSign, ts, false, null);
    }
    
	
    // Gets clientSign and nodeSign(nodeName:nodeSign:ts)
    // Checks if Sign_nodeName(clientSign:TS) == nodeSign
    public static <TMessage> boolean isMessageVerifiedAux(
    		String from,
    		String key,
    		Logger logger,
    		String clientSign, 
    		String nodeSign,
    		String ts,
    		boolean isWriteBack,
    		String hvals){
    	
    	int fieldsNum = 2;
    	if (isWriteBack) {
    		fieldsNum += 1; 
    	} 
				
		if (nodeSign == null 		|| 
			nodeSign.isEmpty() 		||
			(nodeSign.split(":").length != fieldsNum)) {
			if (ByzantineConfig.isErrorLogger) {
				logger.error("Got wrong read signaute structure from: " + from);
				logger.error("Got clientSign: " + clientSign);
				logger.error("Got nodeSign: " + nodeSign);
			}
			return false;
		}
		
		if (clientSign == null || clientSign.isEmpty()) {
			clientSign = ByzantineTools.EMPTY_MESSAGE;
		}
		
		String[] nodeSignSplitted = nodeSign.split(":");
		// Expexcted [WriteBack]:NodeName:NodeSign
		String nodeName = nodeSignSplitted[fieldsNum - 2];
		String nodeSignature = nodeSignSplitted[fieldsNum -1];
		
		boolean res = false;
		
		String data;
		if (hvals == null) {
			data = String.format("%s:%s:%s",key,clientSign,ts);
		} else {
			data = String.format("%s:%s:%s:%s",key,hvals,clientSign,ts);
		}
		if (isWriteBack) {
			data = WRITE_BACK_MESSAGE + ":" + data;
		}
		
		if (ByzantineConfig.isInfoLogger) {
			logger.info("veifying key {} hvals {} clientSign {} ts {}", key, hvals, clientSign, ts);
		}
		
		try {
			res = encryption.verifyData(
					nodeName,
					data.getBytes(),
					nodeSignature.getBytes()	
					);
		} catch (Exception e) {
			if (ByzantineConfig.isErrorLogger)
				logger.error("Exception in verifier {}", e.getMessage());
		} 
		
		if (res == false) {
			if (ByzantineConfig.isErrorLogger)
				logger.error("Verification failed for read from: " + from + " Node sign: " + nodeSign);
		} else {
			if (ByzantineConfig.isInfoLogger)
				logger.info("Verification success for read reponse from: " + from + " Node Name: " + nodeName + " Node ts: " + ts);
		}
		
    	return res;
    }

    // Assume relevant keyspace
    // Checks if Sign_nodeName(clientSign) == signature
    public static boolean isWriteResponseVerified(
    		String nodeName,
    		String signature,
    		byte[] clientSign,
    		Logger logger){
    	
    	if (signature == null || signature.isEmpty() || signature.equals("00")) {
    		return false;
    	}
  	   	
    	boolean res = false;
    	
    	if (ByzantineConfig.isInfoLogger)
			logger.info("Verifying signature on: {}", clientSign);
    	
    	try {
			res = encryption.verifyData(
					nodeName,
					clientSign,
					signature.getBytes()	
					);
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| SignatureException | InvalidKeySpecException e) {
			if (ByzantineConfig.isErrorLogger)
				logger.error("Verification failed for write response.");
			return false;

		}
    	
    	return res;
    }

	private static Cell getCell(ColumnFamily cf, String columnName) {
		CFMetaData cfm = Schema.instance.getCFMetaData(cf.id());
	    return getCell(cf, cfm, columnName);
	}
	
	private static Cell getCell(ColumnFamily cf, CFMetaData cfm, String columnName) {
	    for (Cell c : cf.getSortedColumns()) {
			String name = c.name().cql3ColumnName(cfm).toString();
			if (name.equals(columnName)) {
				return c;
			} 
	    }
	    return null;
	}
    
	public static boolean verifySignature(
			String clientName, 
			DecoratedKey dKey, 
			String value, 
			String ts,
			String sign,
			Logger logger){
		
		String key = getKey(dKey);

		if (ByzantineConfig.isInfoLogger) {
			logger.info("veifying key {} value {} ts {}", key, value, ts);
		}
		
		try {
			return encryption.verifyData(
					clientName, 
					(key + value + ts).getBytes(), 
					sign.getBytes());
		} catch (Exception e) {
			if (ByzantineConfig.isErrorLogger)
				logger.error("Verifier failed {}" ,e.getMessage());
		}
		return false;
	}
	
	public static String getStringFromCell(Cell c){
		ByteBuffer bb = c.value().duplicate();
		final byte[] bytes = new byte[bb.remaining()];
		bb.get(bytes);
		return new String(bytes);
	}
	
	public static MetaVal getMetaValFromCell(Cell c) {
		return parseString(new String(getStringFromCell(c)));
	}
	
	public static Cell getVallCell(ColumnFamily cf, String column) {
		return getCell(cf, VALUE_COLUMN_PREFIX+column);
	}

	public static Cell getMetaCell(ColumnFamily cf, String column) {
		return getCell(cf, META_COLUMN_PREFIX+column);
	}
	
	public static class StoreExtraData {
		public Integer waitForNodes;
		public List<String> list;
		public String symmetricSignatures;
	}

	// Input in the signatures column in the next format waitFor#,blackListNodes,shouldExtractTs
	public static StoreExtraData getExtraData(Mutation mutation, Logger logger) {
		List<String> list = new LinkedList<String>();
		
		ColumnFamily cf = mutation.getColumnFamilies().iterator().next();
		Cell cell = getCell(
				cf, 
				NODES_SIGNATURES_COLUMN);
		if (cell == null) {
			if (ByzantineConfig.isErrorLogger) 
				logger.error("Can't find signatures column for blacklist");
			return null;
		}
		
		String inputString = getStringFromCell(cell);
		if (inputString.isEmpty()) {
			if (ByzantineConfig.isInfoLogger) 
				logger.info("Input is empty");
			return null;
		} 
		
		if (ByzantineConfig.isInfoLogger) 
			logger.info("Got extra data: " + inputString);
		
		// Clear data form the cell
		BufferCell bufferC = (BufferCell)cell;
		bufferC.setValue(ByteBuffer.wrap("".getBytes()));
		
		String symmetricSignatures = null;
		if (ByzantineConfig.isFullMACSignatures 
			&& inputString.contains("#")) {
			String[] splitted = inputString.split("#");
			String symmerticSignature = splitted[0];
			symmetricSignatures = symmerticSignature;
			if (splitted.length > 1) {
				inputString = splitted[splitted.length - 1];
			} else {
				inputString = null;
			}
		}
		
		Integer waitForNodes = null;
		if (inputString != null && !inputString.isEmpty()) {
			String[] splitted = inputString.split(",");
			if (splitted.length != 3) {
				if (ByzantineConfig.isErrorLogger) 
					logger.error("Input should be in the format of waitFor#,blackListNodes,shouldExtractTs: {}", inputString);
				return null;
			}
			
			String waitFor 			= splitted[0];
			String nodes 			= splitted[1];
			String shouldExtractTsS	= splitted[2];
			
			if (!nodes.isEmpty()) {
				for (String node : nodes.split(":")) {
					if (ByzantineConfig.isInfoLogger) 
						logger.info("blacklisting: " + node);
					list.add(node);
				}
			}
		
			if (!shouldExtractTsS.isEmpty()) {
				boolean shouldExtractTs = Boolean.parseBoolean(shouldExtractTsS);
				if (ByzantineConfig.isInfoLogger) 
					logger.info("shouldExtractTs: " + shouldExtractTs);
				if (shouldExtractTs) {
					setTs(cf, logger);
				}
			}
			
			if (!waitFor.isEmpty()) {
				waitForNodes = Integer.parseInt(waitFor);
			}
		}
		
		StoreExtraData data = new StoreExtraData();
		data.list = list;
		data.symmetricSignatures = symmetricSignatures;
		data.waitForNodes = waitForNodes;
		
		if (ByzantineConfig.isInfoLogger) 
			logger.info("returning extra data object.");
		
		return data;
	}
	
	// symmetricSigns = [ip]-[symmetricSign]:[ip]-[symmetricSign]
	private static String getThisNodeSign(String symmerticSignature) {
		if (symmerticSignature == null) {
			return null;
		}
		String thisNodeIp = FBUtilities.getBroadcastAddress().toString();
		for (String pair : symmerticSignature.split(":")) {
			String[] splitted = pair.split("-");
			if (thisNodeIp.equals("/" + splitted[0])) {
				return splitted[1];
			}
		}
		return null;
	}

	public static void setTs(ColumnFamily cf, Logger logger){
		CFMetaData cfm = Schema.instance.getCFMetaData(cf.id());
		List<String> columns = getColumnsSorted(cf, cfm);
		if (columns == null) {
			if (ByzantineConfig.isErrorLogger)
    			logger.error("columns is null");
			return;
		}
		
		for (String column : columns) {
	    	Cell metaCell = getMetaCell(cf, column);
	    	Cell vallCell = getVallCell(cf, column);
	    
	    	if (metaCell == null || vallCell == null) {
	    		if (ByzantineConfig.isErrorLogger)
	    			logger.error("Failed getting cells for column");
	    		continue;
	    	}
	    	
	    	String tsString = getMetaValFromCell(metaCell).ts;
	    	if (tsString == null) {
	    		if (ByzantineConfig.isErrorLogger)
	    			logger.error("ts is null");
	    		continue;
	    	}
	    	
	    	long ts = Long.parseLong(tsString);
	    	
	    	if (ByzantineConfig.isInfoLogger)
	    		logger.info("Old ts: {}, new ts: {}", vallCell.timestamp(), ts);
	    	
	    	// Replacing the cells
	    	((BufferCell)metaCell).setTimestamp(ts);
	    	((BufferCell)vallCell).setTimestamp(ts);
	    	
	    	if (ByzantineConfig.isInfoLogger)
    			logger.info("Injected timestamps into column#: " + column);
		}
	}
	
	public static void extractInjectedDate(List<ReadCommand> initialCommands, Logger logger) {
		for (ReadCommand rc : initialCommands){
			if (ByzantineTools.isRelevantKeySpace(rc.ksName)){
				String keyString = ByzantineTools.getKeyData(rc.key);
				ByzantineTools.KeyMetaData keyMeta = ByzantineTools.parseInjectedKey(keyString);;
                // Clear the injected data
				if (keyMeta == null) {
					logger.error("Invaliad byzantine read");
					continue;
				}
				rc.key 			= ByteBuffer.wrap(keyMeta.key.getBytes());
				rc.ts 			= keyMeta.ts;
				rc.columns		= keyMeta.valNums;
				rc.clientName 	= keyMeta.clientId;
				rc.blackList 	= keyMeta.blackList;
				if (ByzantineConfig.isInfoLogger) {
    				logger.info("[ronili]  Handling read " + keyString + " columns: " + rc.columns + " clientName: " + rc.clientName);
    			}
			}
		}
	}
	
	public static String computeCassandraHash(Logger logger, String text){
		if (ByzantineConfig.isInfoLogger) {
			logger.info("computing cassandra hash on: {}", text);
		}
		
		try {
			MessageDigest m = MessageDigest.getInstance("MD5");
			byte[] digest = m.digest(text.getBytes());
			return new String(digest);
		} catch (NoSuchAlgorithmException e) {
			if (ByzantineConfig.isErrorLogger) {
				logger.error("[ronili]  computeCassandraHash fail " + e.getMessage());
			}
			return null;
		}
	}
	
//    private static String computeHashOnMessageValues(Logger logger, Row row, String columns) {
//		ColumnFamily cf = row.cf;
//		return computeHashOnMessageValues(logger, cf, columns);
//	}
    
    public static String computeHashOnMessageValues(Logger logger, ColumnFamily cf, String columns) {
		if (cf == null) {
			if (ByzantineConfig.isErrorLogger) {
				logger.error("Got null cf");
			}
			return "";
		}
		
		String vals = "";
		
		if (columns.equals(REQUEST_ALL_FIELDS)) {
			CFMetaData cfm = Schema.instance.getCFMetaData(cf.id());
			for (Cell c : cf.getSortedColumns()) {
				String name = c.name().cql3ColumnName(cfm).toString();
				if (name.startsWith(VALUE_COLUMN_PREFIX)) {
					String value = ByzantineTools.getStringFromCell(c);
					vals += value;
					if (ByzantineConfig.isInfoLogger)
						logger.info("add val" + name);
				}
				
			}
		} else {
			for (String column : columns.split(":")) {
				Cell valCell = ByzantineTools.getVallCell(cf, column);
				if (valCell == null) continue;
				
				String value = ByzantineTools.getStringFromCell(valCell);
				vals += value;
				if (ByzantineConfig.isInfoLogger)
					logger.info("add val field" + column);
			}
		}
		
		return computeCassandraHash(logger, vals);
	}
    
    private static String getRelevantClientSign(Logger logger, ColumnFamily cf, String columns) {
		if (cf == null) return null;
		
		String signs = "";
		
		if (columns.equals(REQUEST_ALL_FIELDS)) {
			CFMetaData cfm = Schema.instance.getCFMetaData(cf.id());
			for (Cell c : cf.getSortedColumns()) {
				String name = c.name().cql3ColumnName(cfm).toString();
				if (name.startsWith(META_COLUMN_PREFIX)) {
					String metaString = ByzantineTools.getStringFromCell(c);
					signs += parseString(metaString).signautre;
				}
			}
		} else {
			for (String column : columns.split(":")) {
				Cell metaCell = ByzantineTools.getMetaCell(cf, column);
				if (metaCell == null) continue;
				
				String metaString = ByzantineTools.getStringFromCell(metaCell);
				signs += parseString(metaString).signautre;
			}
		}
		
		return signs;
	}
}
