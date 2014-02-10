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
			throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, wrongKeyLengthException, passphraseTooLargeException, IOException {

		CryptoGuts cg = new CryptoGuts();
		cg.encrypt(passphrase, plaintext, keylength);
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput out = null;
		byte[] yourBytes = null;
		try {
		  out = new ObjectOutputStream(bos);   
		  out.writeObject(cg.ciphertext.getIVspec());
		  yourBytes = bos.toByteArray();
		} finally {
		  try {
		    if (out != null) {
		      out.close();
		    }
		  } catch (IOException ex) {
		    // ignore close exception
		  }
		  try {
		    bos.close();
		  } catch (IOException ex) {
		    // ignore close exception
		  }
		}
		
		return (cg.getSalt()+"\n#\n"+hexConverter.toHex(yourBytes)+"\n#\n"+hexConverter.toHex(cg.ciphertext.getCiphertextByteArr()));
	}
	
	
	private String decrypt (String passphrase, int keylength, String data) throws NoSuchAlgorithmException, wrongKeyLengthException, passphraseTooLargeException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		String[] components = data.split("#");
		
		CryptoGuts cg = new CryptoGuts();
		
		cg.ciphertext.setKey(cg.generateKey(passphrase, keylength, components[0]));
		
		ByteArrayInputStream bis = new ByteArrayInputStream(hexConverter.toByte(components[1]));
		ObjectInput in = null;
		IvParameterSpec ivparam = null;
		try {
		  in = new ObjectInputStream(bis);
		  ivparam = (IvParameterSpec) in.readObject();
		} finally {
		  try {
		    bis.close();
		  } catch (IOException ex) {
		    // ignore close exception
		  }
		  try {
		    if (in != null) {
		      in.close();
		    }
		  } catch (IOException ex) {
		    // ignore close exception
		  }
		}
		cg.ciphertext.setIVspec(ivparam);
		
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
