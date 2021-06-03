package etf.openpgp.js170758d.controller;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
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
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

//java imports
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

public class SignAndEncrypt {
	/*
	public void fDecryptOnePassSignatureLocal(InputStream encryptedInputStream, InputStream signPublicKeyInputStream,
			InputStream secretKeyInputStream, String secretKeyPassphrase, OutputStream targetStream) throws Exception {

		Security.addProvider(new BouncyCastleProvider());

		// The decrypted results.
		// StringBuffer result = new StringBuffer();
		// The private key we use to decrypt contents.
		PGPPrivateKey privateKey = null;
		// The PGP encrypted object representing the data to decrypt.
		PGPPublicKeyEncryptedData encryptedData = null;

		// Get the list of encrypted objects in the message. The first object in
		// the
		// message might be a PGP marker, however, so we skip it if necessary.
		PGPObjectFactory objectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(encryptedInputStream));
		Object firstObject = objectFactory.nextObject();
		System.out.println("firstObject is " + firstObject);
		PGPEncryptedDataList dataList = (PGPEncryptedDataList) (firstObject instanceof PGPEncryptedDataList
				? firstObject
				: objectFactory.nextObject());

		// Find the encrypted object associated with a private key in our key
		// ring.
		@SuppressWarnings("rawtypes")
		Iterator dataObjectsIterator = dataList.getEncryptedDataObjects();
		PGPSecretKeyRingCollection secretKeyCollection = new PGPSecretKeyRingCollection(
				PGPUtil.getDecoderStream(secretKeyInputStream));
		while (dataObjectsIterator.hasNext()) {
			encryptedData = (PGPPublicKeyEncryptedData) dataObjectsIterator.next();
			System.out.println("next data object is " + encryptedData);
			PGPSecretKey secretKey = secretKeyCollection.getSecretKey(encryptedData.getKeyID());

			if (secretKey != null) {
				// This object was encrypted for this key. If the passphrase is
				// incorrect, this will generate an error.
				privateKey = secretKey.extractPrivateKey(secretKeyPassphrase.toCharArray(), "BC");
				break;
			}
		}

		if (privateKey == null) {
			System.out.println();
			throw new RuntimeException("secret key for message not found");
		}

		// Get a handle to the decrypted data as an input stream
		InputStream clearDataInputStream = encryptedData.getDataStream(privateKey, "BC");
		PGPObjectFactory clearObjectFactory = new PGPObjectFactory(clearDataInputStream);
		Object message = clearObjectFactory.nextObject();

		System.out.println("message for PGPCompressedData check is " + message);

		// Handle case where the data is compressed
		if (message instanceof PGPCompressedData) {
			PGPCompressedData compressedData = (PGPCompressedData) message;
			objectFactory = new PGPObjectFactory(compressedData.getDataStream());
			message = objectFactory.nextObject();
		}

		System.out.println("message for PGPOnePassSignature check is " + message);

		PGPOnePassSignature calculatedSignature = null;
		if (message instanceof PGPOnePassSignatureList) {
			calculatedSignature = ((PGPOnePassSignatureList) message).get(0);
			PGPPublicKeyRingCollection publicKeyRingCollection = new PGPPublicKeyRingCollection(
					PGPUtil.getDecoderStream(signPublicKeyInputStream));
			PGPPublicKey signPublicKey = publicKeyRingCollection.getPublicKey(calculatedSignature.getKeyID());
			calculatedSignature.initVerify(signPublicKey, "BC");
			message = objectFactory.nextObject();
		}

		System.out.println("message for PGPLiteralData check is " + message);

		// We should only have literal data, from which we can finally read the
		// decrypted message.
		if (message instanceof PGPLiteralData) {
			InputStream literalDataInputStream = ((PGPLiteralData) message).getInputStream();
			int nextByte;

			while ((nextByte = literalDataInputStream.read()) >= 0) {
				// InputStream.read guarantees to return a byte (range 0-255),
				// so we
				// can safely cast to char.
				calculatedSignature.update((byte) nextByte); // also update
				// calculated
				// one pass
				// signature
				// result.append((char) nextByte);
				// add to file instead of StringBuffer
				targetStream.write((char) nextByte);
			}
			targetStream.close();
		} else {
			throw new RuntimeException("unexpected message type " + message.getClass().getName());
		}

		if (calculatedSignature != null) {
			PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();
			System.out.println("signature list (" + signatureList.size() + " sigs) is " + signatureList);
			PGPSignature messageSignature = (PGPSignature) signatureList.get(0);
			System.out.println("verification signature is " + messageSignature);
			if (!calculatedSignature.verify(messageSignature)) {
				throw new RuntimeException("signature verification failed");
			}
		}

		if (encryptedData.isIntegrityProtected()) {
			if (encryptedData.verify()) {
				System.out.println("message integrity protection verification succeeded");
			} else {
				throw new RuntimeException("message failed integrity check");
			}
		} else {
			System.out.println("message not integrity protected");
		}

		// close streams
		clearDataInputStream.close();

	}
	*/
}
