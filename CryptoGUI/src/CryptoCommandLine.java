import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;


public class CryptoCommandLine {
	public CryptoCommandLine(String[] args) {
		/*
		 * First [0] parameter is mode (0 for encrypt, 1 for decrypt)
		 * Second [1] parameter is passphrase (string)
		 * Third [2] parameter is keylength (int)
		 * Fourth [3] parameter is whether you're giving a file location for the message to encrypt or the actual string to encrypt
		 * Fifth [4] parameter is either file location or the message to encrypt (string)
		 * Sixth [5] parameter is where you want the encryption to be stored
		 */
		if (args.length < 5){
			System.err.print("Invalid number of parameters. Please input the passphrase (string), key length (int),\n"
					+"whether or not you're asking to encrypt a file on your drive (1) or a string (0),\nand then"+
					" either the location of the file to encrypt(string of the form C:\\[stuff]) \nor your plaintext (string).");
		}
		else if (args.length == 5) {
			outputToCL(args);
		}
		else if (args.length == 6) {
			outputToFile(args);
		}
		else {
			System.err.print("Invalid number of parameters. Please input the passphrase (string), key length (int),\n"
					+"whether or not you're asking to encrypt a file on your drive (1) or a string (0),\n"+
					" either the location of the file to encrypt(string of the form C:\\[stuff]) \nor your plaintext (string),"
					+ "and then, unless you want stuff spit out to the command line, the desired location for the ciphertext (string of the form C:\\[stuff]).");
		}
	}

	private void outputToFile(String[] args) {
		PrintWriter writer = null;
		try {
			writer = new PrintWriter(args[5], "UTF-8");
		} catch (FileNotFoundException | UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		if (Integer.parseInt(args[0]) == 0) {
			writer.print(encrypt(args));
		}
		else if (Integer.parseInt(args[0]) == 1) {
			writer.print(decrypt(args));
		}
		else {
			System.err.print("The ony two modes are encrypt (enc) and decrypt (dec).");
		}
		writer.close();
	}

	private void outputToCL(String[] args) {
		if (Integer.parseInt(args[0]) == 0) {
			System.out.print(encrypt(args));
		}
		else if (Integer.parseInt(args[0]) == 1) {
			System.out.print(decrypt(args));
		}
		else {
			System.err.print("The ony two modes are encrypt (enc) and decrypt (dec).");
		}
	}

	private String encrypt(String[] args) {
		/*
		 * First [0] parameter is mode (0 for encrypt, 1 for decrypt)
		 * Second [1] parameter is passphrase (string)
		 * Third [2] parameter is keylength (int)
		 * Fourth [3] parameter is whether you're giving a file location for the message to encrypt or the actual string to encrypt
		 * Fifth [4] parameter is either file location or the message to encrypt (string)
		 */
		if (Integer.parseInt(args[3]) == 0) { // encrypt plaintext from command line
			return encrypt(args[1], Integer.parseInt(args[2]), args[4]);
		}
		else if (Integer.parseInt(args[3]) == 1) { // encrypt plaintext from file location
			String plaintext = "";
			Scanner in;
			try {
				in = new Scanner(new FileReader(args[4]));
				while (in.hasNext()) {
					plaintext += in.nextLine()+"\n";
				}
				in.close();
			} catch (FileNotFoundException | NumberFormatException e) {
				e.printStackTrace();
			}
			
			return encrypt(args[1], Integer.parseInt(args[2]), plaintext);
		}
		else {
			System.err.print("Invalid option; either you want to encrypt a file (1) or a message from the command line (0)");
			return null;
		}
	}
	
	private String encrypt (String passphrase, int keylength, String plaintext) {
		CryptoGuts cg = new CryptoGuts();
		try {
			cg.encrypt(passphrase, plaintext, keylength);
			
			return (cg.getSalt()+"\n#\n"+hexConverter.toHex(cg.ciphertext.getCiphertextByteArr()));
		} catch (InvalidKeyException | NumberFormatException
				| InvalidAlgorithmParameterException
				| IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException
				| NoSuchAlgorithmException | wrongKeyLengthException
				| passphraseTooLargeException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private String decrypt(String[] args) {
		// TODO write method for decrypting either a ciphertext from the command line or from a file
		// what happens when you want to decrypt? need to process the command line (how to separate salt from the message? can you have a multiline message in the args array? should just be another string, but I don't know how to test this)
		// when you're decrypting frmo a file, need to take the passphrase entered, the salt from the top of the file, and re-generate the key so you can invoke the decrypt method in cryptoguts!
	
		return null;
	}
}
