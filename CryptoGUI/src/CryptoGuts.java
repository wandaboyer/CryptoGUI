import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
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
	protected Ciphertext ciphertext;
	private String salt;
	
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
	public void encrypt(String passphrase, String message, int keylenchoice) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, wrongKeyLengthException, passphraseTooLargeException {
		ciphertext = new Ciphertext();
		
		ciphertext.setKey(generateKey(passphrase, keylenchoice));
		ciphertext.setIVspec(generateIV());
		
		cipher.init(Cipher.ENCRYPT_MODE, ciphertext.getKey(), ciphertext.getIVspec());
        ciphertext.setCiphertextByteArr(cipher.doFinal(message.getBytes()));
        
		//return ciphertext;
	}
	
	

	public String decrypt(Ciphertext ciphertext) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.DECRYPT_MODE,ciphertext.getKey(), ciphertext.getIVspec());
        String plaintext = new String(this.cipher.doFinal(ciphertext.getCiphertextByteArr()));
        return plaintext;
	}

	private SecretKeySpec generateKey(String passphrase, int keylenchoice) throws UnsupportedEncodingException, NoSuchAlgorithmException, wrongKeyLengthException, passphraseTooLargeException {
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
				throw new wrongKeyLengthException();
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
				throw new wrongKeyLengthException();
			}
			else if (keylenchoice == 24) {
				//JOptionPane.showMessageDialog(this,"Cannot use this key length!", "wrongKeyLength", JOptionPane.ERROR_MESSAGE);
				throw new wrongKeyLengthException();
			}
			else if (keylenchoice == 32) {
				r = new SecureRandom();
				salt = new byte[32-passphrase.length()];
				r.nextBytes(salt);
			}
		}
		else {
			//JOptionPane.showMessageDialog(this,"Choose a passphrase that is less than or equal to 32 bytes in length!", "passphraseTooLarge", JOptionPane.ERROR_MESSAGE);
			throw new passphraseTooLargeException();
		}
		this.salt = hexConverter.toHex(salt);
		byte[] morphedPassphrase = (passphrase+salt.toString()).getBytes("UTF-8");
		MessageDigest sha = MessageDigest.getInstance("SHA-1");
		morphedPassphrase = sha.digest(morphedPassphrase);
		morphedPassphrase = Arrays.copyOf(morphedPassphrase, keylenchoice);
        return new SecretKeySpec(morphedPassphrase, "AES");
	}
	
	protected SecretKeySpec generateKey(String passphrase, int keylenchoice, String salt) throws UnsupportedEncodingException, NoSuchAlgorithmException, wrongKeyLengthException, passphraseTooLargeException {
		this.salt = salt;
		byte[] morphedPassphrase = (passphrase+salt.toString()).getBytes("UTF-8");
		MessageDigest sha = MessageDigest.getInstance("SHA-1");
		morphedPassphrase = sha.digest(morphedPassphrase);
		morphedPassphrase = Arrays.copyOf(morphedPassphrase, keylenchoice);
        return new SecretKeySpec(morphedPassphrase, "AES");
	}
	
	private IvParameterSpec generateIV() {
		byte[] iv = new byte[this.cipher.getBlockSize()];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}
	
	protected String getSalt() {
		return this.salt;
	}
}
