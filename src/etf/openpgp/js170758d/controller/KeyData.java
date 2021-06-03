package etf.openpgp.js170758d.controller;

import java.math.BigInteger;

public class KeyData {
	private String name;
	private String email;
	private String keyID;
	private boolean isSecret;
	
	public KeyData(String userData, String keyID, boolean isSecret) {
		super();
		String[] data = parseData(userData);
		this.name = data[0];
		this.email = data[1];
		this.keyID = keyID;
		this.isSecret = isSecret;
	}
	
	public KeyData(String name, String email, String keyID, boolean isSecret) {
		super();
		this.name = name;
		this.email = email;
		this.keyID = keyID;
		this.isSecret = isSecret;
	}
	
	public static String[] parseData(String data) {
		String[] retValue = data.split("<");
		retValue[1] = retValue[1].substring(0, retValue[1].length()-1);
		
		return retValue;
	}
	
	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return keyID.toUpperCase() + "<" + email + ">";
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getKeyID() {
		return keyID;
	}

	public void setKeyID(String keyID) {
		this.keyID = keyID;
	}

	public boolean isSecret() {
		return isSecret;
	}

	public void setSecret(boolean isSecret) {
		this.isSecret = isSecret;
	}
	
	public static Long getLongFromHexString(String hexValue) {
		BigInteger keyID = new BigInteger(hexValue, 16);
		return keyID.longValue();
	}
	
	@Override
	public boolean equals(Object obj) {
		// TODO Auto-generated method stub
		return ((KeyData)obj).keyID.equals(keyID);
	}
}
