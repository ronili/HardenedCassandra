package cs.technion;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

// Java 8
// import java.util.Base64;
// Java 7
import javax.xml.bind.DatatypeConverter;

import java.util.HashMap;
import java.util.Map;

public class Encryption {
	//TODO: move to a better place.
	static String publicKeysFolder = ByzantineConfig.SIGNATURES_PUBLIC;
	//static String privatePath = "C:\\Dropbox\\CassandraWork\\Certificates\\node1-server-keystore.jks";
	//static String alias = "node1";
	//static String keystorePass = "byzantineKeypass";
	
	private PrivateKey prv = null;
	private PublicKey pub = null;
	private Map<String, PublicKey> publicKeys = null;
	private boolean isInit = false;
	
	// Singelton
    private static Encryption instance = null;

    private Encryption(){}
   
    public boolean isInit() {
    	return isInit;
    }
    
    public static Encryption getInstance(){
    	if (instance == null) {
    		instance = new Encryption();
    	}
    	
        return instance;
    }
   
    public static void initS(String privatePath, String alias, String keystorePass) throws Exception {
    	if (instance == null) {
    		instance = new Encryption();
    	}
    	instance.init(privatePath, alias, keystorePass);
    }
    
    public void init(String privatePath, String alias, String keystorePass) throws Exception {
		prv = Encryption.loadPrivateKey(privatePath, alias, keystorePass);
		if (prv == null) {
			System.err.println("Failed obtaining keystore");
		}
		publicKeys = getAllPublicKeys();
		
		if (publicKeys == null) {
			System.err.println("Failed obtaining certificates");
		}
		System.out.println("Loaded certificates: " + publicKeys.size());
		isInit = true;
    }
    
    private static Map<String,PublicKey> getAllPublicKeys(){
    	Map<String,PublicKey> mapping = new HashMap<String,PublicKey>();
    	Path dir = FileSystems.getDefault().getPath(publicKeysFolder);
    	try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.cer")) {
    	    for (Path entry: stream) {
    	    	String certPath = entry.toString();
    	        String name = entry.getFileName().toString().split(".cer")[0];
    	        PublicKey pk = null;
    	        try {
					pk = loadPublicKey(certPath);
				} catch (Exception e) {
					System.err.println("Failed loading cert: " + certPath);
					continue;
				}
    	        
    	        if (pk == null){
    	        	System.err.println("Failed loading cert (null): " + certPath);
					continue;
    	        }
    	        
    	        mapping.put(name, pk);
    	    }
    	} catch (IOException x) {
    	    // IOException can never be thrown by the iteration.
    	    // In this snippet, it can // only be thrown by newDirectoryStream.
    	    System.err.println(x);
    	}
    	
    	return mapping;
    }
    
	public static PrivateKey loadPrivateKey(String path, String alias, String keystorePass) throws Exception{
		KeyStore ks = KeyStore.getInstance("JKS");
		FileInputStream ksfis = new FileInputStream(path); 
		BufferedInputStream ksbufin = new BufferedInputStream(ksfis);
	
		ks.load(ksbufin, keystorePass.toCharArray());
		PrivateKey priv = (PrivateKey) ks.getKey(alias, keystorePass.toCharArray());
		
		return priv;
	}
	
	public static PublicKey loadPublicKey(String path) throws Exception{
		FileInputStream certfis = new FileInputStream(path);
		java.security.cert.CertificateFactory cf =
		    java.security.cert.CertificateFactory.getInstance("X.509");
		java.security.cert.Certificate cert =  cf.generateCertificate(certfis);
		PublicKey pub = cert.getPublicKey();
		
		return pub;
	}
		
	public byte[] signData(byte[] data) throws Exception 
	{
		Signature signature = Signature.getInstance(ByzantineConfig.SIGNING_ALGO);
		
		signature.initSign(prv);
		signature.update(data);
		// Java 8
		//return Base64.getEncoder().encode(signature.sign());
		// Java 7
		return DatatypeConverter.printBase64Binary(signature.sign()).getBytes();
	}

	public boolean verifyData(String signer, byte[] data, byte[] sigBytes) throws 
		NoSuchAlgorithmException, 
		InvalidKeyException, 
		SignatureException, 
		InvalidKeySpecException 
	{
		if (!publicKeys.containsKey(signer)){
			System.err.println("No such signer exists in the system:" + signer);
			return false;
		}
		
		Signature signature = Signature.getInstance(ByzantineConfig.SIGNING_ALGO);
		
		signature.initVerify(publicKeys.get(signer));
		signature.update(data);
		// Java 8
		// return signature.verify(Base64.getDecoder().decode(sigBytes));
		// Java 7
		byte[] decoded = DatatypeConverter.parseBase64Binary(new String(sigBytes));
		return signature.verify(decoded);
	}
		
}