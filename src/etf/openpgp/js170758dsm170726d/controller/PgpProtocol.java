package etf.openpgp.js170758dsm170726d.controller;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.WatchEvent.Kind;
import java.nio.file.WatchEvent.Modifier;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.general.TripleDES;  //Pazi na ovaj deo 
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi.SHA1;
import org.bouncycastle.jcajce.provider.symmetric.DESede;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;
import org.omg.CosNaming.IstringHelper;

import etf.openpgp.js170758dsm170726d.view.MainWindow;

public class PgpProtocol extends PgpAbstract {
	private PGPPublicKeyRingCollection publicKeyRingCollection;
	private PGPSecretKeyRingCollection secretKeyRingCollection;
	public PgpProtocol() {
		super();
		readFiles();
	}
	public PGPPrivateKey getPrivateKey(long keyID, char[] pass) {
		try {
			PGPSecretKey secretKey = secretKeyRingCollection.getSecretKey(keyID);

			if (secretKey == null) {
				return null;
			}

			return secretKey.extractPrivateKey(
					new JcePBESecretKeyDecryptorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
														.build(pass));
		} catch (PGPException e) {
			
			//Alert("Couldn't find the private key");
			// TODO Auto-generated catch block
			// e.printStackTrace();
			return null;
		}
	}
	private void readFiles() {
		try {
			File publicFile = new File(PUBLIC_KEYS_FILE);
			publicFile.createNewFile();

			File secretFile = new File(SECRET_KEYS_FILE);
			secretFile.createNewFile();

			InputStream publicFileStream = new FileInputStream(publicFile);
			InputStream secretFileStream = new FileInputStream(secretFile);

			publicKeyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicFileStream),
					new JcaKeyFingerprintCalculator());

			secretKeyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(secretFileStream),
					new JcaKeyFingerprintCalculator());
			publicFileStream.close();
			secretFileStream.close();
		} catch (IOException | PGPException e) {
			Alert("Key files have been corrupted");
			// TODO Auto-generated catch block
			//e.printStackTrace();
		}
	}
	public List<KeyData> getSecretKeys() {
		List<KeyData> keyList = new LinkedList<KeyData>();
		Iterator<PGPSecretKeyRing> iter = secretKeyRingCollection.getKeyRings();
		while (iter.hasNext()) {
			PGPSecretKeyRing secretKeyRing = iter.next();
			PGPSecretKey secretKey = secretKeyRing.getSecretKey();
			String keyID = Long.toHexString(secretKey.getKeyID());
			String keyUser = secretKey.getUserIDs().next();
			KeyData data = new KeyData(keyUser, keyID, true);
			keyList.add(data);
		}

		return keyList;
	}
	public List<KeyData> getPublicKeys() {
		List<KeyData> keyList = new LinkedList<KeyData>();
		Iterator<PGPPublicKeyRing> iter = publicKeyRingCollection.getKeyRings();
		while (iter.hasNext()) {
			PGPPublicKeyRing publicKeyRing = iter.next();
			PGPPublicKey publicKey = publicKeyRing.getPublicKey();
			String keyID = Long.toHexString(publicKey.getKeyID());
			String keyUser = publicKey.getUserIDs().next();
			KeyData data = new KeyData(keyUser, keyID, true);
			keyList.add(data);
		}

		return keyList;
	}
	public KeyData generateKeyPair(String name, String email, String password, int dsaBitLength, int elGamalBitLength) {
		KeyPair dsaKeyPair = getKeyPair("DSA", dsaBitLength);
		KeyPair elGamalKeyPair = getKeyPair("ELGAMAL", elGamalBitLength);

		try {
			PGPKeyPair pgpDsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKeyPair, new Date());
			PGPKeyPair pgpElGamalKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elGamalKeyPair, new Date());

			PGPDigestCalculator sha1DigestCalculator = new JcaPGPDigestCalculatorProviderBuilder().build()
					.get(HashAlgorithmTags.SHA1);

			String identity = name + "<" + email + ">";
			PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
					pgpDsaKeyPair, identity, sha1DigestCalculator, null, null,
					new JcaPGPContentSignerBuilder(pgpDsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
					new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1DigestCalculator).setProvider("BC")
							.build(password.toCharArray()));

			keyRingGenerator.addSubKey(pgpElGamalKeyPair);

			secretKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRingCollection,
					keyRingGenerator.generateSecretKeyRing());
			publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRingCollection,
					keyRingGenerator.generatePublicKeyRing());

			savePublicKeys();
			saveSecretKeys();

			return new KeyData(name, email, Long.toHexString(pgpDsaKeyPair.getKeyID()), true);

		} catch (PGPException e) {
			// TODO Auto-generated catch block
			Alert("Couldn't generate key pair");
			e.printStackTrace();
			return null;
		}

	}
	private void savePublicKeys() {
		OutputStream publicOut;
		try {
			publicOut = new FileOutputStream(PUBLIC_KEYS_FILE);
			publicOut = new ArmoredOutputStream(publicOut);

			publicKeyRingCollection.encode(publicOut);

			publicOut.close();
		} catch (IOException e) {
			Alert("Couldn't save public key");
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	private void saveSecretKeys() {
		try {
			OutputStream secretOut = new FileOutputStream(SECRET_KEYS_FILE);
			secretOut = new ArmoredOutputStream(secretOut);

			secretKeyRingCollection.encode(secretOut);

			secretOut.close();
		} catch (IOException e) {
			Alert("Couldn't save private key");
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	@Override
	public void deleteKeyPair(long keyID) {
		// TODO Auto-generated method stub
		try {
			if (publicKeyRingCollection.contains(keyID)) {
				PGPPublicKeyRing keyRing = publicKeyRingCollection.getPublicKeyRing(keyID);
				publicKeyRingCollection = PGPPublicKeyRingCollection.removePublicKeyRing(publicKeyRingCollection,
						keyRing);
				savePublicKeys();
			}
			if (secretKeyRingCollection.contains(keyID)) {
				PGPSecretKeyRing keyRing = secretKeyRingCollection.getSecretKeyRing(keyID);
				secretKeyRingCollection = PGPSecretKeyRingCollection.removeSecretKeyRing(secretKeyRingCollection,
						keyRing);
				saveSecretKeys();
			}
		} catch (PGPException e) {
			Alert("Nije obrisan privatni par kljuceva");
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	@Override
	public void exportPublicKey(String fileName, long keyID) {
		// TODO Auto-generated method stub
		OutputStream publicOut;
		try {
			publicOut = new FileOutputStream(fileName + PUBLIC_KEY_APPEND);
			publicOut = new ArmoredOutputStream(publicOut);
			publicKeyRingCollection.getPublicKeyRing(keyID).encode(publicOut);
			publicOut.close();
		} catch (PGPException | IOException e) {
			Alert("Couldn't export public key");
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {

		}
	}
	@Override
	public void exportSecretKey(String fileName, long keyID) {
		// TODO Auto-generated method stub
		OutputStream secretOut;
		try {
			secretOut = new FileOutputStream(fileName + SECRET_KEY_APPEND);
			secretOut = new ArmoredOutputStream(secretOut);
			secretKeyRingCollection.getSecretKeyRing(keyID).encode(secretOut);
			secretOut.close();
		} catch (PGPException | IOException e) {
			
			Alert("Couldn't save private key");
			
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {

		}
	}
	@Override
	public KeyData importPublicKey(String fileName) {
		try {
			File publicFile = new File(fileName);
			InputStream publicFileStream = new FileInputStream(publicFile);
			PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(PGPUtil.getDecoderStream(publicFileStream),
					new JcaKeyFingerprintCalculator());

			publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRingCollection,
					publicKeyRing);

			savePublicKeys();
			publicFileStream.close();

			PGPPublicKey publicKey = publicKeyRing.getPublicKey();
			String keyID = Long.toHexString(publicKey.getKeyID());
			String keyUser = publicKey.getUserIDs().next();
			return new KeyData(keyUser, keyID, true);
		} catch (IOException e) {
			Alert("Couldn't import public key");
			// TODO Auto-generated catch block
			// e.printStackTrace();
			return null;
		}
	}
	@Override
	public KeyData importSecretKey(String fileName) {
		// TODO Auto-generated method stub
		try {
			File secretFile = new File(fileName);
			InputStream secretFileStream = new FileInputStream(secretFile);

			PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(PGPUtil.getDecoderStream(secretFileStream),
					new JcaKeyFingerprintCalculator());

			secretKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRingCollection,
					secretKeyRing);

			saveSecretKeys();
			secretFileStream.close();

			PGPSecretKey secretKey = secretKeyRing.getSecretKey();
			String keyID = Long.toHexString(secretKey.getKeyID());
			String keyUser = secretKey.getUserIDs().next();
			return new KeyData(keyUser, keyID, true);
		} catch (IOException | PGPException e) {
			Alert("Couldn't import private key");
			// TODO Auto-generated catch block
			// e.printStackTrace();
			return null;
		}
	}
	private PGPPublicKey getEncryptionKey(Long keyID) {

		try {
			PGPPublicKeyRing publicKeyRing = publicKeyRingCollection.getPublicKeyRing(keyID);
			Iterator<PGPPublicKey> keyIter = publicKeyRing.getPublicKeys();

			while (keyIter.hasNext()) {
				PGPPublicKey publicKey = keyIter.next();
				if (publicKey.isEncryptionKey()) {
					return publicKey;
				}
			}
			return null;
		} catch (PGPException e) {
			e.printStackTrace();
			return null;
		}

	}

	private PGPSecretKey getSigningKey(Long keyID) {

		try {
			PGPSecretKeyRing secretKeyRing = secretKeyRingCollection.getSecretKeyRing(keyID);

			Iterator<PGPSecretKey> keyIter = secretKeyRing.getSecretKeys();

			while (keyIter.hasNext()) {
				PGPSecretKey secretKey = keyIter.next();

				if (secretKey.isSigningKey()) {
					return secretKey;
				}
			}
			return null;
		} catch (PGPException e) {
			Alert("Couldn't find signing key");
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

	}

	public boolean isSecretKey(long keyID) {
		try {
			return secretKeyRingCollection.contains(keyID);
		} catch (PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
	}

	private KeyPair getKeyPair(String algorithm, int bitLength) {
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC");
			keyPairGenerator.initialize(bitLength);
			return keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			Alert("Couldn't generate key pair");
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

	}
	@SuppressWarnings("resource")
	protected void verifyMessage(PGPCompressedData compressedData, String outputFile) {
		try {
			//Promena stringa bez .out dodatka
			outputFile = outputFile.substring(0,outputFile.length()-4);
			//
			JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(compressedData.getDataStream());

			PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) objectFactory.nextObject();
			PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);
			PGPLiteralData literalData = (PGPLiteralData) objectFactory.nextObject();

			InputStream literalInputStream = literalData.getInputStream();
			int ch;

			System.out.println(outputFile);
			PGPPublicKey publicKey = publicKeyRingCollection.getPublicKey(onePassSignature.getKeyID());
			FileOutputStream outputStream = new FileOutputStream(outputFile);

			onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);

			while ((ch = literalInputStream.read()) >= 0) {
				onePassSignature.update((byte) ch);
				outputStream.write(ch);
			}
			outputStream.close();

			PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();

			if (onePassSignature.verify(signatureList.get(0))) {
				showMessage("Signature verified. File signed by " + publicKey.getUserIDs().next());
			} else {
				throw new Exception("Signature verification failed.");
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			Alert(e.getMessage());
			//e.printStackTrace();
		}

	}
    protected void verifySignature(String inputFile, PGPSignatureList signatureList) throws Exception {
		try {

			InputStream inputStream = new FileInputStream(new File(inputFile.substring(0, inputFile.length()-4)));
			int ch;

			PGPSignature signature = signatureList.get(0);
			PGPPublicKey publicKey = publicKeyRingCollection.getPublicKey(signature.getKeyID());
			
			signature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
			
			while ((ch = inputStream.read()) >= 0) {
				signature.update((byte) ch);
				//outputStream.write(ch);
			}
			//outputStream.close();

			if (signature.verify()) {
				showMessage("Signature verified. File signed by " + publicKey.getUserIDs().next());
			} else {
				throw new Exception("Signature verification failed.");
			}
		} catch (Exception e) {
			Alert(e.getMessage());
			// TODO Auto-generated catch block
		}
    }
	@SuppressWarnings("deprecation")
	public void signAndEncrypt(String outputFileName, String inputFileName, String algorithm, Long signature,
			char[] password, List<Long> encryptFor, boolean compress, boolean convertToRadix64, boolean encrypt)
			throws Exception {

		boolean sign = signature != null;
		OutputStream outputStream = new FileOutputStream(outputFileName);
		InputStream inputStream = new FileInputStream(inputFileName);
		int BUFFER_SIZE = 1 << 16;

		if (convertToRadix64)
			outputStream = new ArmoredOutputStream(outputStream);

		PGPEncryptedDataGenerator encryptedDataGenerator = null;
		OutputStream encryptedOut = null;

		if (encrypt) {
			int algoID = PGPEncryptedData.CAST5;
			if (algorithm.equals("TripleDES")) {
				algoID = PGPEncryptedData.TRIPLE_DES;
			}
			encryptedDataGenerator = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(algoID)
					.setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));

			for (Long keyID : encryptFor) {
				PGPPublicKey publicKey = getEncryptionKey(keyID);
				if (publicKey != null) {

					encryptedDataGenerator
							.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));
				}

			}

			encryptedOut = encryptedDataGenerator.open(outputStream, new byte[BUFFER_SIZE]);
		}

		int compressAlg = PGPCompressedData.UNCOMPRESSED;
		if (compress) {
			compressAlg = PGPCompressedData.ZIP;
		}

		OutputStream compressedOut = null;
		PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(compressAlg);
		if (encrypt) {
			compressedOut = compressedDataGenerator.open(encryptedOut);
		} else {
			compressedOut = compressedDataGenerator.open(outputStream);
		}

		PGPSignatureGenerator signatureGenerator = null;
		if (sign) {
			PGPSecretKey pgpSecKey = getSigningKey(signature);
			if (pgpSecKey == null)
				throw new Exception("No secret key could be found in specified key ring collection.");

			PGPPrivateKey pgpPrivKey = pgpSecKey
					.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password));
			signatureGenerator = new PGPSignatureGenerator(
					new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1)
							.setProvider("BC"));

			signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
			for (@SuppressWarnings("rawtypes")
			Iterator i = pgpSecKey.getPublicKey().getUserIDs(); i.hasNext();) {
				String userId = (String) i.next();
				PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
				spGen.setSignerUserID(false, userId);
				signatureGenerator.setHashedSubpackets(spGen.generate());
				break;
			}
			signatureGenerator.generateOnePassVersion(false).encode(compressedOut);
		}

		PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
		File actualFile = new File(outputFileName);
		OutputStream literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY, inputFileName,
				new Date(actualFile.lastModified()), new byte[BUFFER_SIZE]);

		byte[] buf = new byte[BUFFER_SIZE];
		int len;
		while ((len = inputStream.read(buf, 0, buf.length)) > 0) {
			literalOut.write(buf, 0, len);
			if (sign) {
				signatureGenerator.update(buf, 0, len);
			}
		}
		literalOut.close();
		literalDataGenerator.close();
		if (sign) {
			signatureGenerator.generate().encode(compressedOut);
		}

		compressedOut.close();
		compressedDataGenerator.close();
		if (encrypt) {
			encryptedOut.close();
			encryptedDataGenerator.close();
		}

		if (convertToRadix64)
			outputStream.close();

	}

	public void decryptAndVerify(String inputFile) throws Exception {
		
		InputStream inputStream = new FileInputStream(inputFile);

		JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(inputStream));
		Object firstObject = objectFactory.nextObject();

		Object message = null;

		if (firstObject instanceof PGPSignatureList) {
			verifySignature(inputFile, (PGPSignatureList)firstObject);
		} else if (firstObject instanceof PGPCompressedData) {
			verifyMessage((PGPCompressedData) firstObject, inputFile);
		} else {
			//Promena stringa bez .out dodatka
			String outputFile = inputFile.substring(0, inputFile.length()-4);
			OutputStream outputStream = new FileOutputStream(outputFile);
			
			boolean signed = false;
			PGPPrivateKey privateKey = null;
			PGPSecretKey secretKey = null;
			PGPPublicKeyEncryptedData encryptedData = null;
			PGPEncryptedDataList dataList = (PGPEncryptedDataList) (firstObject instanceof PGPEncryptedDataList
					? firstObject
					: objectFactory.nextObject());

			
			@SuppressWarnings("rawtypes")
			Iterator dataObjectsIterator = dataList.getEncryptedDataObjects();

			while (dataObjectsIterator.hasNext()) {
				encryptedData = (PGPPublicKeyEncryptedData) dataObjectsIterator.next();
				secretKey = secretKeyRingCollection.getSecretKey(encryptedData.getKeyID());

				if (secretKey != null) {
					char[] pass = showPasswordDialog(secretKey.getKeyID());
					privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
							.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pass));
					break;
				}
			}

			if (privateKey == null) {
				System.out.println();
				throw new RuntimeException("Secret key for message not found");
			}

			InputStream clearDataInputStream = null;
			if (privateKey != null) {
				clearDataInputStream = encryptedData.getDataStream(
						new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));
			}

			JcaPGPObjectFactory clearObjectFactory = null;
			if (clearDataInputStream == null) {
				clearObjectFactory = objectFactory;
			} else {
				clearObjectFactory = new JcaPGPObjectFactory(clearDataInputStream);
			}

			message = clearObjectFactory.nextObject();

			//System.out.println("Message for PGPCompressedData check is " + message);

			if (message instanceof PGPCompressedData) {
				PGPCompressedData compressedData = (PGPCompressedData) message;
				objectFactory = new JcaPGPObjectFactory(compressedData.getDataStream());
				message = objectFactory.nextObject();
			}

			//System.out.println("Message for PGPOnePassSignature check is " + message);

			PGPOnePassSignature calculatedSignature = null;
			PGPPublicKey signPublicKey = null;
			
			if (message instanceof PGPOnePassSignatureList) {

				calculatedSignature = ((PGPOnePassSignatureList) message).get(0);
				signPublicKey = publicKeyRingCollection.getPublicKey(calculatedSignature.getKeyID());
				calculatedSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), signPublicKey);
				message = objectFactory.nextObject();
				signed = true;
			}

			//System.out.println("Message for PGPLiteralData check is " + message);

			if (message instanceof PGPLiteralData) {
				InputStream literalDataInputStream = ((PGPLiteralData) message).getInputStream();
				int nextByte;

				while ((nextByte = literalDataInputStream.read()) >= 0) {

					if (signed) {
						calculatedSignature.update((byte) nextByte);
					}

					outputStream.write((char) nextByte);
				}
				outputStream.close();
			} else {
				throw new RuntimeException("Unexpected message type " + message.getClass().getName());
			}
			
			String info = "";

			if (calculatedSignature != null) {
				PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();

				//System.out.println("Signature list (" + signatureList.size() + " sigs) is " + signatureList);
				PGPSignature messageSignature = (PGPSignature) signatureList.get(0);
				//System.out.println("Verification signature is " + messageSignature);
				if (!calculatedSignature.verify(messageSignature)) {
					throw new RuntimeException("Signature verification failed");
				}
				else if(signed){
					info += "Signature verified. File signed by " + signPublicKey.getUserIDs().next() + "\n";
				}
			}

			if (encryptedData.isIntegrityProtected()) {
				if (encryptedData.verify()) {
					info += "Message integrity checked. File encrypted for " +
					secretKeyRingCollection.getSecretKeyRing(secretKey.getKeyID()).getSecretKeys().next().getUserIDs().next();
				} else {
					throw new RuntimeException("Message failed integrity check");
				}
			} else {
				info += "Message not integrity protected\n";
			}
			showMessage(info);
			// close streams
			if (clearDataInputStream != null)
				clearDataInputStream.close();
		}
		inputStream.close();
		
		
	}

	private char[] showPasswordDialog(Long keyID) {
		JPasswordField passField = new JPasswordField();
		int ok = JOptionPane.showConfirmDialog(null, passField, "Enter Password", JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.PLAIN_MESSAGE);
		while (ok == JOptionPane.OK_OPTION) {
			PGPPrivateKey privateKey = getPrivateKey(keyID, passField.getPassword());
			if (privateKey != null) {
				return passField.getPassword();
			} else {
				JOptionPane.showConfirmDialog(null, "Wrong password!", "Error", JOptionPane.DEFAULT_OPTION);
				passField.setText(null);
				ok = JOptionPane.showConfirmDialog(null, passField, "Enter Password", JOptionPane.OK_CANCEL_OPTION,
						JOptionPane.PLAIN_MESSAGE);
			}
		}
		return null;
	}

}
