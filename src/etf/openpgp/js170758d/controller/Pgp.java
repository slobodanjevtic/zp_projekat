package etf.openpgp.js170758d.controller;

import java.util.List;

import org.bouncycastle.openpgp.PGPKeyPair;

public interface Pgp {


	
	public KeyData generateKeyPair(String name, 
								String email, 
								String password, 
								int dsaBitLength, 
								int elGamalBitLength);
	
	public void deleteKeyPair(long keyID);
	
	public void exportPublicKey(String fileName, 
								long keyID);
	
	public void exportSecretKey(String fileName, 
								long keyID);
	
	public KeyData importPublicKey(String fileName);
	
	public KeyData importSecretKey(String fileName);
	
	public KeyData importKey(String fileName);
	
	public void sendMessage(String fileName, 
							Long signatureKeyID,
							char[] pass,
							List<Long> encryptKeyIDs,
							String algorithm,
							boolean compress, 
							boolean convertToRadix64);
	
	public void receiveMessage(String fileName, char[] pass);
	
}
