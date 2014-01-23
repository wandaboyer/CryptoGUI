import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoGuts {
	private Cipher cipher;
	private AlgorithmParameterSpec ivspec;
	private SecretKeySpec key;
    public byte[] ciphertext; // Need to maintain byte array of ciphertext so that padding will be maintained
	
    //call const from const
    protected CryptoGuts () {
    	Security.addProvider(new BouncyCastleProvider());
        // creates a cipher object with the chosen provider
        try {
        	//this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
			this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    // move keylen to constructor
    
    // return salt, iv, keylen AND the ciphertext - create a new class to return, EncryptedObj... tell that obj to write and read itself from a file, and hex
	public byte[] encrypt(String passphrase, String message, int keylenchoice) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException {
		generateKey(passphrase, keylenchoice);

		byte[] iv = new byte[this.cipher.getBlockSize()];
		new SecureRandom().nextBytes(iv);
		ivspec = new IvParameterSpec(iv);
		
		cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
        ciphertext = cipher.doFinal(message.getBytes());
		return ciphertext;
	}
	
	public String decrypt() throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
        String plaintext = new String(this.cipher.doFinal(this.ciphertext));
        return plaintext;
	}

	private void generateKey(String passphrase, int keylenchoice) throws UnsupportedEncodingException, NoSuchAlgorithmException {
		Random r;
		byte[] salt = null;
		// make some kind of key from the passphrase field (needs to be 7 bytes), then pass to secretkeyspec
		if (passphrase.length() < 16) {
			if (keylenchoice == 16) {
				// then generate a random salt with length of the difference between the passphrase and 16
				r = new SecureRandom();
				salt = new byte[16-passphrase.length()];
				r.nextBytes(salt);
			}
			else if (keylenchoice == 24) {
				r = new SecureRandom();
				salt = new byte[24-passphrase.length()];
				r.nextBytes(salt);
			}
			else if (keylenchoice == 32) {
				r = new SecureRandom();
				salt = new byte[32-passphrase.length()];
				r.nextBytes(salt);
			}
		}
		else if (passphrase.length() < 24) {
			if (keylenchoice == 16) {
				//JOptionPane.showMessageDialog(this,"Cannot use this key length!", "wrongKeyLength", JOptionPane.ERROR_MESSAGE);
			}
			else if (keylenchoice == 24) {
				r = new SecureRandom();
				salt = new byte[24-passphrase.length()];
				r.nextBytes(salt);
			}
			else if (keylenchoice == 32) {
				r = new SecureRandom();
				salt = new byte[32-passphrase.length()];
				r.nextBytes(salt);
			}
		}
		else if (passphrase.length() <= 32) {
			if (keylenchoice == 16) {
				//JOptionPane.showMessageDialog(this,"Cannot use this key length!", "wrongKeyLength", JOptionPane.ERROR_MESSAGE);
			}
			else if (keylenchoice == 24) {
				//JOptionPane.showMessageDialog(this,"Cannot use this key length!", "wrongKeyLength", JOptionPane.ERROR_MESSAGE);
			}
			else if (keylenchoice == 32) {
				r = new SecureRandom();
				salt = new byte[32-passphrase.length()];
				r.nextBytes(salt);
			}
		}
		else {
			//JOptionPane.showMessageDialog(this,"Choose a passphrase that is less than or equal to 32 bytes in length!", "passphraseTooLarge", JOptionPane.ERROR_MESSAGE);
		}
		
		byte[] morphedPassphrase = (passphrase+salt.toString()).getBytes("UTF-8");
		MessageDigest sha = MessageDigest.getInstance("SHA-1");
		morphedPassphrase = sha.digest(morphedPassphrase);
		morphedPassphrase = Arrays.copyOf(morphedPassphrase, keylenchoice);
		//System.out.println(this.key);
        this.key = new SecretKeySpec(morphedPassphrase, "AES");
        //System.out.println(this.key);
	}
	
	
	/*public static void main(String[] args){
       	CryptoGuts app = new CryptoGuts();
       	try {
			app.ciphertext = app.encrypt("sasdf", "fart", 32);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException
				| IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
       	try {
			System.out.println(app.decrypt());
		} catch (InvalidKeyException | InvalidAlgorithmParameterException
				| IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
       	
 	}*/
}
