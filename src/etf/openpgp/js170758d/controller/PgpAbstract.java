package etf.openpgp.js170758d.controller;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;


public abstract class PgpAbstract implements Pgp {
	protected static final String PUBLIC_KEYS_FILE = "keys/public_keys.txt";
	protected static final String SECRET_KEYS_FILE = "keys/secret_keys.txt";
	protected static final String PUBLIC_KEY_APPEND = "_public.asc";
	protected static final String SECRET_KEY_APPEND = "_secret.asc";
	protected static final String ENCRYPTED_MESSAGE_APPEND = ".gpg";
	protected static final String TEMP_APPEND = "_temp";
	
	public PgpAbstract() {
        Security.addProvider(new BouncyCastleProvider());
	}
	

	@Override
	public void sendMessage(String fileName, 
							Long signature, 
							char[] pass,
							List<Long> encryptFor,
							String algorithm,
							boolean compress, 
							boolean convertToRadix64) {

		boolean encrypt = encryptFor != null && !encryptFor.isEmpty();
		
		try {
			signAndEncrypt(fileName + ENCRYPTED_MESSAGE_APPEND, fileName, algorithm, 
								signature, pass, encryptFor, compress, 
								convertToRadix64, encrypt);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public void receiveMessage(String fileName) {
		//decryptMessage(fileName, "out.txt", pass);
		//System.out.println(fileName);
		//String fileName2 = "info.txt_temp.gpg";
		//verifyMessage2(null, fileName, fileName + ".out");
		try {
			decryptAndVerify(fileName, fileName + ".out");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public KeyData importKey(String fileName) {
		KeyData secretKeyData = importSecretKey(fileName);
		KeyData publicKeyData = importPublicKey(fileName);
		
		if(secretKeyData == null) {
			return publicKeyData;
		}
		return secretKeyData;
	}
	
	public abstract boolean isSecretKey(long keyID);
	
	protected abstract void verifyMessage(PGPCompressedData compressedData, String outputFile);
	
	protected abstract void verifyMessage2(PGPSignatureList signatureList, InputStream inputStream, OutputStream outputStream, String outputFile);
	protected abstract void verifyMessage3(String inputFile, String outputFile);		
	
	public abstract void signAndEncrypt(String outputFileName, String inputFileName, String algorithm,
			Long signature, char[] password, List<Long> encryptFor, boolean compress,
			boolean convertToRadix64, boolean encrypt) throws Exception;

	public abstract void decryptAndVerify(String inputFile, String outputFile) throws Exception;
}
