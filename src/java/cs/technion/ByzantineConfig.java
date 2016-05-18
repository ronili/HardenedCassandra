package cs.technion;

public class ByzantineConfig {
	final public static boolean isInfoLogger = true;
	final public static boolean isErrorLogger = true;
	
	final public static boolean isSignaturesLogic = true;
	final public static boolean isDataPathLogic = true;
	
	final public static boolean isCommandPath = true;
	
	final public static boolean isWriteOption2 = true;
	final public static boolean isReadOption2 = true;
	final public static boolean isReadOption2b = false;
	
	final public static boolean isMacSignatures = false;
	final public static boolean isFullMACSignatures = false;
	
	final public static String SIGNATURES_PUBLIC = "[Path_To_The_Cetrificates_Folder]";
	final public static String SIGNATURES_SUFFIX = "sign";
	final public static String SIGNING_ALGO = "SHA256withECDSA";
	final public static String SYM_SINGING_ALGO = "HmacSHA256";
}
