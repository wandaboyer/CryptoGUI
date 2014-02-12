import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.util.encoders.Base64;


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
				Integer.parseInt(args[0]) == 0 ? true : false, //true is encrypt mode, false is decrypt mode
				args[1], 
				Integer.parseInt(args[2]), 
				Integer.parseInt(args[3]) == 0 ? true : false, // true means that the command line argument is a filename, false is that the argument is the data
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
			throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, wrongKeyLengthException, passphraseTooLargeException, IOException {

		CryptoGuts cg = new CryptoGuts();
		byte[] ivspec = cg.encrypt(passphrase, plaintext, keylength);
		
		//TODO need some way to store the ciphertext (and possibly the ivspec?) in the proper encoding so that padding is preserved, because there's a pad block corrupted error
		return (cg.getSalt()+"\n#\n"+(new String(Base64.encode(ivspec)))+"\n#\n"+(new String(Base64.encode(cg.ciphertext.getCiphertextByteArr()))));
		//return (cg.getSalt()+"\n#\n"+ (new sun.misc.BASE64Encoder.encodeBuffer(ivspec)) +"\n#\n"+(new sun.misc.BASE64Encoder.encodeBuffer(cg.ciphertext.getCiphertextByteArr())));
	}
	
	
	private String decrypt (String passphrase, int keylength, String data) throws NoSuchAlgorithmException, wrongKeyLengthException, passphraseTooLargeException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		String[] components = data.split("\n#\n");
		
		CryptoGuts cg = new CryptoGuts();
		//System.out.println(components[0]+" "+components[1]+" " + components[2] + " "+ keylength + " " + passphrase);
		cg.ciphertext = new Ciphertext();
		
		cg.ciphertext.setKey(cg.generateKey(passphrase, keylength, components[0]));
		
		cg.ciphertext.setIVspec(new IvParameterSpec(Base64.decode(components[1])));
		
		cg.ciphertext.setCiphertextByteArr(Base64.decode(components[2].getBytes()));
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
