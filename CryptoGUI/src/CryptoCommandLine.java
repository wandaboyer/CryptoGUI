import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;


public class CryptoCommandLine {
	public CryptoCommandLine(String[] args) throws Exception {
		/*
		 * First [0] parameter is mode (0 for encrypt, 1 for decrypt)
		 * Second [1] parameter is passphrase (string)
		 * Third [2] parameter is keylength (int)
		 * Fourth [3] parameter is whether you're giving a file location for the message to encrypt or the actual string to encrypt
		 * Fifth [4] parameter is either file location or the message to encrypt (string)
		 * Sixth [5] parameter is where you want the encryption to be stored
		 */
		
		this(
				Integer.parseInt(args[0]) == 0 ? true : false, 
				args[1], 
				Integer.parseInt(args[2]), 
				Integer.parseInt(args[3]) == 0 ? true : false, 
				args[4], 
				args.length == 6 ? args[5] : null);
	}

	public CryptoCommandLine(boolean encryptMode, String passphrase, int keylength, boolean messageDataIsFilename, String messageData, String outFile) throws Exception {
		String data = (messageDataIsFilename ? readFile(messageData) : messageData);
		
		String result = (encryptMode ? encrypt(passphrase, keylength, data) : decrypt(passphrase, keylength, data));
		
		
		if (outFile == null) {
			System.out.print(result);
		}
		else {
			PrintWriter writer = null;
			try {
				writer = new PrintWriter(outFile, "UTF-8");
			} catch (FileNotFoundException | UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			
			writer.print(result);
			
			writer.close();
		}
	}
		
	private String encrypt (String passphrase, int keylength, String plaintext) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, wrongKeyLengthException, passphraseTooLargeException {

		CryptoGuts cg = new CryptoGuts();
		cg.encrypt(passphrase, plaintext, keylength);
		
		return (cg.getSalt()+"\n#\n"+cg.ciphertext.getIVspec().toString()+"\n#\n"+hexConverter.toHex(cg.ciphertext.getCiphertextByteArr()));
	}
	
	
	private String decrypt (String passphrase, int keylength, String data) throws UnsupportedEncodingException, NoSuchAlgorithmException, wrongKeyLengthException, passphraseTooLargeException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String[] components = data.split("#");
		
		CryptoGuts cg = new CryptoGuts();
		
		cg.ciphertext.setKey(cg.generateKey(passphrase, keylength, components[0]));
		cg.ciphertext.setIVspec(new IvParameterSpec(components[1].getBytes()));
		cg.ciphertext.setCiphertextByteArr(components[2].getBytes());
		return (cg.decrypt(cg.ciphertext));
	}

	private String readFile(String filename) {
		String plaintext = "";
		Scanner in;
		try {
			in = new Scanner(new FileReader(filename));
			while (in.hasNext()) {
				plaintext += in.nextLine()+"\n";
			}
			in.close();
		} catch (FileNotFoundException | NumberFormatException e) {
			e.printStackTrace();
		}
		return plaintext;
	}

}
