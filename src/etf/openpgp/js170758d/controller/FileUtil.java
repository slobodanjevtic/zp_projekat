package etf.openpgp.js170758d.controller;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SignatureException;

import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.Strings;

public class FileUtil {

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

	public static void processLine(PGPSignature sig, byte[] line) throws SignatureException, IOException {
		int length = getLengthWithoutWhiteSpace(line);
		if (length > 0) {
			sig.update(line, 0, length);
		}
	}

	public static void processLine(OutputStream aOut, PGPSignatureGenerator sGen, byte[] line)
			throws SignatureException, IOException {
		int length = getLengthWithoutWhiteSpace(line);
		if (length > 0) {
			sGen.update(line, 0, length);
		}

		aOut.write(line, 0, line.length);
	}

	public static int getLengthWithoutSeparatorOrTrailingWhitespace(byte[] line) {
		int end = line.length - 1;

		while (end >= 0 && isWhiteSpace(line[end])) {
			end--;
		}

		return end + 1;
	}

	public static boolean isLineEnding(byte b) {
		return b == '\r' || b == '\n';
	}

	public static int getLengthWithoutWhiteSpace(byte[] line) {
		int end = line.length - 1;

		while (end >= 0 && isWhiteSpace(line[end])) {
			end--;
		}

		return end + 1;
	}

	public static boolean isWhiteSpace(byte b) {
		return isLineEnding(b) || b == '\t' || b == ' ';
	}

	public static int readInputLine(ByteArrayOutputStream bOut, InputStream fIn) throws IOException {
		bOut.reset();

		int lookAhead = -1;
		int ch;

		while ((ch = fIn.read()) >= 0) {
			bOut.write(ch);
			if (ch == '\r' || ch == '\n') {
				lookAhead = readPassedEOL(bOut, ch, fIn);
				break;
			}
		}

		return lookAhead;
	}

	public static int readInputLine(ByteArrayOutputStream bOut, int lookAhead, InputStream fIn) throws IOException {
		bOut.reset();

		int ch = lookAhead;

		do {
			bOut.write(ch);
			if (ch == '\r' || ch == '\n') {
				lookAhead = readPassedEOL(bOut, ch, fIn);
				break;
			}
		} while ((ch = fIn.read()) >= 0);

		if (ch < 0) {
			lookAhead = -1;
		}

		return lookAhead;
	}

	public static int readPassedEOL(ByteArrayOutputStream bOut, int lastCh, InputStream fIn) throws IOException {
		int lookAhead = fIn.read();

		if (lastCh == '\r' && lookAhead == '\n') {
			bOut.write(lookAhead);
			lookAhead = fIn.read();
		}

		return lookAhead;
	}

	public static byte[] getLineSeparator() {
		String nl = Strings.lineSeparator();
		byte[] nlBytes = new byte[nl.length()];

		for (int i = 0; i != nlBytes.length; i++) {
			nlBytes[i] = (byte) nl.charAt(i);
		}

		return nlBytes;
	}

	public static byte[] compressFile(String fileName, int algorithm) throws IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
		PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));
		comData.close();
		return bOut.toByteArray();
	}

}
