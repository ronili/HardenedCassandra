package cs.technion;

import org.apache.cassandra.db.Mutation;
import org.apache.cassandra.db.ReadCommand;
import org.apache.cassandra.utils.FBUtilities;
import org.slf4j.Logger;

public class ByzantineCommands {
	
	private static final String COMMANDS_KEYSPACE = "commands";
	private static final String COMMANDS_COLUMN_NODES = "nodes";
	private static final String COMMANDS_COLUMN_PARAMS = "params";
	// Using mutation key instead.
	//final private static String COMMANDS_COLUMN_TYPE = "type";
	// Usage un-implemented
	//final private static String COMMANDS_COLUMN_CLIENTS = "clients";

	//make generic
	private static int WRITES_TO_IGNORE_SILENCE = 0;
	private static int WRITES_TO_NOT_RESPOND = 0;
	private static int WRITES_TO_NOT_RESPOND_FROM = 0;
	private static int RETURN_BAD_SIGN_WRITE = 0;
	private static int RETURN_BAD_SIGN_WRITE_FROM = 0;
	private static int READS_TO_NOT_RESPOND = 0;
	private static int READS_TO_NOT_RESPOND_FROM = 0;
	private static int RETURN_BAD_SIGN_READ = 0;
	private static int RETURN_BAD_SIGN_READ_FROM = 0;
	private static int RETURN_BAD_DIGEST = 0;
	private static int RETURN_BAD_DIGEST_FROM = 0;
	
	public static boolean shouldIgnoreThisWriteSilence(Mutation mutation, Logger logger) {
		boolean decision = false;
		
		if (ByzantineTools.isRelevantKeySpace(mutation.getKeyspaceName()) &&
			WRITES_TO_IGNORE_SILENCE > 0) {
			decision = true;
			WRITES_TO_IGNORE_SILENCE--;
			if (ByzantineConfig.isInfoLogger) 
				logger.info("shouldIgnoreThisWriteSilence: True");
		}
		
		return decision;
	}
	
	public static boolean shouldIgnoreThisWriteLoud(Mutation mutation, Logger logger) {
		if (!ByzantineTools.isRelevantKeySpace(mutation.getKeyspaceName())) {
			return false;
		}
		
		//logger.error("WRITES_TO_NOT_RESPOND_FROM: " + WRITES_TO_NOT_RESPOND_FROM);
		if (WRITES_TO_NOT_RESPOND_FROM > 0) {
			WRITES_TO_NOT_RESPOND_FROM--;
			return false;
		}
		
		if (WRITES_TO_NOT_RESPOND > 0) {
			WRITES_TO_NOT_RESPOND--;
			if (ByzantineConfig.isInfoLogger) 
				logger.info("shouldIgnoreThisWriteLoud = True");
			return true;
		}
		
		return false;
	}
	
	public static boolean shouldReturnBadSignWrite(Mutation mutation, Logger logger) {
		if (!ByzantineTools.isRelevantKeySpace(mutation.getKeyspaceName())) {
			return false;
		}
		
		if (RETURN_BAD_SIGN_WRITE_FROM > 0) {
			RETURN_BAD_SIGN_WRITE_FROM--;
			return false;
		}
		
		if (RETURN_BAD_SIGN_WRITE > 0) {
			RETURN_BAD_SIGN_WRITE--;
			if (ByzantineConfig.isInfoLogger) 
				logger.info("shouldReturnBadSignWRITE = True");
			return true;
		}
		
		return false;
	}
	
	// Doesn't assume relevant keyspace
	public static boolean shouldIgnoreThisRead(ReadCommand command, Logger logger) {
		if (!ByzantineTools.isRelevantKeySpace(command.ksName)) {
			return false;
		}
		
		//logger.error("READS_TO_NOT_RESPOND_FROM: " + READS_TO_NOT_RESPOND_FROM);
		if (READS_TO_NOT_RESPOND_FROM > 0) {
			READS_TO_NOT_RESPOND_FROM--;
			return false;
		}
		
		if (READS_TO_NOT_RESPOND > 0) {
			READS_TO_NOT_RESPOND--;
			if (ByzantineConfig.isInfoLogger) 
				logger.info("shouldIgnoreThisRead = True");
			return true;
		}
		
		return false;
	}
	
	// Assume relevant keyspace
	public static boolean shouldReturnBadSignRead(ReadCommand command, Logger logger) {
		if (RETURN_BAD_SIGN_READ_FROM > 0) {
			RETURN_BAD_SIGN_READ_FROM--;
			return false;
		}
		
		if (RETURN_BAD_SIGN_READ > 0) {
			RETURN_BAD_SIGN_READ--;
			if (ByzantineConfig.isInfoLogger) 
				logger.info("shouldReturnBadSign = True");
			return true;
		}
		
		return false;
	}
	
	// Assume relevant keyspace
	public static boolean shouldReturnBadDigest(ReadCommand command, Logger logger) {
		if (RETURN_BAD_DIGEST_FROM > 0) {
			RETURN_BAD_DIGEST_FROM--;
			return false;
		}
		
		if (RETURN_BAD_DIGEST > 0) {
			RETURN_BAD_DIGEST--;
			if (ByzantineConfig.isInfoLogger) 
				logger.info("shouldReturnBadDigest = True");
			return true;
		}
		
		return false;
	}
	
	// Returns true if command exhausted.
	public static boolean handleCommandPath(String ks, Mutation mutation, Logger logger){
		if (!ks.equals(COMMANDS_KEYSPACE)) {
			return false;
		}
		if (ByzantineConfig.isInfoLogger) 
			logger.info("[ronili] Handling command path");
		
		String myAddr = FBUtilities.getBroadcastAddress().toString();
		String targetNodes = ByzantineTools.getData(mutation, COMMANDS_COLUMN_NODES, logger);
		String commandType = ByzantineTools.getKeyData(mutation); // COMMANDS_COLUMN_TYPE
		String commandParms = ByzantineTools.getData(mutation, COMMANDS_COLUMN_PARAMS, logger);
		if (targetNodes == null || commandType == null) {
			if (ByzantineConfig.isErrorLogger) 
				logger.error("Couldn't get command info, commandType {}, targetNodes {}",commandType, targetNodes);
			return true;
		}
		
		String[] relevantNodes = targetNodes.split(":"); 
		
		// TODO: move strings to constants
		for (String node : relevantNodes){
			if (node.equals(myAddr)) {
				switch (commandType) {
					case "0":
						handleSilenceWrite(logger);
						break;
					case "1":
						handleDontRespondWrite(logger, commandParms);
						break;
					case "return_bad_sign_write":
						handleReturnBadSignWrite(logger, commandParms);
						break;
					case "dont_respond_read":
						handleDontRespondRead(logger, commandParms);
						break;
					case "return_bad_sign_read":
						handleReturnBadSignRead(logger, commandParms);
						break;
					case "return_bad_digest":
						handleReturnBadDigest(logger, commandParms);
						break;
					case "clean_all":
						handleCleanAll(logger, commandParms);
						break;
					default:
						if (ByzantineConfig.isErrorLogger) 
							logger.error("Unknown command type");
						break;
					}
				break;
			}
		}
		
		return true;
	}
	
	private static void handleSilenceWrite(Logger logger) {
		WRITES_TO_IGNORE_SILENCE++;
		if (ByzantineConfig.isInfoLogger) 
			logger.info("handleSilenceWrite command, Updated WRITES_TO_IGNORE: " + WRITES_TO_IGNORE_SILENCE);
	}
	
	private static void handleDontRespondWrite(Logger logger, String commandParms) {
		String[] splitted = commandParms.split(":");
		WRITES_TO_NOT_RESPOND += Integer.parseInt(splitted[0]);
		WRITES_TO_NOT_RESPOND_FROM += Integer.parseInt(splitted[1]);
		
		if (ByzantineConfig.isInfoLogger) {
			logger.info("handleDontRespondWrite command, Updated globals:");
			logger.info("	WRITES_TO_NOT_RESPOND: " + WRITES_TO_NOT_RESPOND);
			logger.info("	WRITES_TO_NOT_RESPOND_FROM: " + WRITES_TO_NOT_RESPOND_FROM);
		}
	}
	
	private static void handleDontRespondRead(Logger logger, String commandParms) {
		String[] splitted = commandParms.split(":");
		READS_TO_NOT_RESPOND += Integer.parseInt(splitted[0]);
		READS_TO_NOT_RESPOND_FROM += Integer.parseInt(splitted[1]);
		
		if (ByzantineConfig.isInfoLogger) {
			logger.info("handleDontRespondRead command, Updated globals:");
			logger.info("	READS_TO_NOT_RESPOND: " + READS_TO_NOT_RESPOND);
			logger.info("	READS_TO_NOT_RESPOND_FROM: " + READS_TO_NOT_RESPOND_FROM);
		}
	}

	private static void handleReturnBadSignWrite(Logger logger, String commandParms) {
		String[] splitted = commandParms.split(":");
		RETURN_BAD_SIGN_WRITE += Integer.parseInt(splitted[0]);
		RETURN_BAD_SIGN_WRITE_FROM += Integer.parseInt(splitted[1]);
		
		if (ByzantineConfig.isInfoLogger) {
			logger.info("handleReturnBadSignWRITE command, Updated globals:");
			logger.info("	RETURN_BAD_SIGN_WRITE: " + RETURN_BAD_SIGN_WRITE);
			logger.info("	RETURN_BAD_SIGN_WRITE_FROM: " + RETURN_BAD_SIGN_WRITE_FROM);
		}
	}
	
	private static void handleReturnBadSignRead(Logger logger, String commandParms) {
		String[] splitted = commandParms.split(":");
		RETURN_BAD_SIGN_READ += Integer.parseInt(splitted[0]);
		RETURN_BAD_SIGN_READ_FROM += Integer.parseInt(splitted[1]);
		
		if (ByzantineConfig.isInfoLogger) {
			logger.info("handleReturnBadSignRead command, Updated globals:");
			logger.info("	RETURN_BAD_SIGN_READ: " + RETURN_BAD_SIGN_READ);
			logger.info("	RETURN_BAD_SIGN_READ_FROM: " + RETURN_BAD_SIGN_READ_FROM);
		}
	}
	
	private static void handleReturnBadDigest(Logger logger, String commandParms) {
		String[] splitted = commandParms.split(":");
		RETURN_BAD_DIGEST += Integer.parseInt(splitted[0]);
		RETURN_BAD_DIGEST_FROM += Integer.parseInt(splitted[1]);
		if (ByzantineConfig.isInfoLogger) {
			logger.info("handleReturnBadDigest command, Updated globals:");
			logger.info("	RETURN_BAD_DIGEST: " + RETURN_BAD_DIGEST);
			logger.info("	RETURN_BAD_DIGEST_FROM: " + RETURN_BAD_DIGEST_FROM);
		}
	}
	
	private static void handleCleanAll(Logger logger, String commandParms) {
		WRITES_TO_IGNORE_SILENCE = 0;
		WRITES_TO_NOT_RESPOND = 0;
		WRITES_TO_NOT_RESPOND_FROM = 0;
		READS_TO_NOT_RESPOND = 0;
		READS_TO_NOT_RESPOND_FROM = 0;
		RETURN_BAD_SIGN_READ = 0;
		RETURN_BAD_SIGN_READ_FROM = 0;
		RETURN_BAD_DIGEST = 0;
		RETURN_BAD_DIGEST_FROM = 0;
		RETURN_BAD_SIGN_WRITE = 0;
		RETURN_BAD_SIGN_WRITE_FROM = 0;
		
		if (ByzantineConfig.isInfoLogger) 
			logger.info("handleCleanAll command, Updated globals:");
	}
}
