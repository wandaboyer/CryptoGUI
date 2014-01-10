import javax.swing.*;

import java.awt.*;
import java.awt.event.*;
import java.text.*;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class CryptoGUI extends JFrame implements ActionListener
{
	private static final String salt = "NaCl";
    private static final int iterations = 2000;
    private static final int keyLength = 256;
    private static final SecureRandom random = new SecureRandom();

	public static void main(String[] args)
	{
		CryptoGUI app = new CryptoGUI();
	}
	
	private JTextField passphraseField;
	private JTextArea messageArea, ciphertextArea, decryptedArea;
	private JButton decryptButton, encryptButton;
	private JCheckBox successfulDecryption;
	
	public CryptoGUI()
	{
		// Set up the outer window
		super("CryptoGUI");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setSize(500, 700);
		setLocation(100,100);
		setResizable(false);
		setVisible(true);
		
		// Set up the content area
		Container contentPane = getContentPane();
		contentPane.setBackground(Color.WHITE);		
		FlowLayout layoutMgr = new FlowLayout(FlowLayout.LEFT);
		contentPane.setLayout(layoutMgr);

		// Input passphrase
		JPanel passphrasePanel = new JPanel();
		passphrasePanel.setBackground(Color.WHITE);
		passphrasePanel.add(new JLabel("Enter passphrase:"));
		passphraseField = new JTextField("", 15);
		passphrasePanel.add(passphraseField);
		contentPane.add(passphrasePanel);
		
		// Input message to encrypt
		JPanel messagePanel = new JPanel();
		messagePanel.add(new JLabel("Enter message to Encrypt:"));
		messageArea = new JTextArea("", 10, 15);
		messagePanel.add(messageArea);
		contentPane.add(messagePanel);
		
		// How do I make the layout nicer for positioning of buttons, etc, other than making new panels?
		JPanel encryptPanel = new JPanel();
		encryptPanel.setBackground(Color.WHITE);
		encryptPanel.setLayout(new FlowLayout());
		encryptButton = new JButton("Encrypt");
		encryptButton.addActionListener(this);
		encryptPanel.add(encryptButton);
		contentPane.add(encryptPanel);
		
		
		// Resulting ciphertext
		JPanel ciphertextPanel = new JPanel();
		ciphertextPanel.add(new JLabel("Resulting ciphertext:"));
		ciphertextArea = new JTextArea("", 10, 15);
		ciphertextArea.setEditable(false);
		ciphertextPanel.add(ciphertextArea);
		contentPane.add(ciphertextPanel);
		
		JPanel decryptPanel = new JPanel();
		decryptPanel.setBackground(Color.WHITE);
		decryptPanel.setLayout(new FlowLayout());
		decryptButton = new JButton("Decrypt");
		decryptButton.addActionListener(this);
		decryptPanel.add(decryptButton);
		contentPane.add(decryptPanel);

		// Should result in original message
		JPanel decryptedPanel = new JPanel();
		decryptedPanel.add(new JLabel("Result of decryption:"));
		decryptedArea = new JTextArea("", 10, 15);
		decryptedArea.setEditable(false);
		decryptedPanel.add(decryptedArea);
		contentPane.add(decryptedPanel);
		
		// Is the decrypted message the same as the original message?
		JPanel successfulDecryptionPanel = new JPanel();
		successfulDecryptionPanel.add(new JLabel("Is the decrypted message the same as the original?"));
		successfulDecryption = new JCheckBox();
		successfulDecryption.setSelected(false);
        successfulDecryptionPanel.add(successfulDecryption);
		contentPane.add(successfulDecryptionPanel);
		
		// Make the main window show the updated content pane
		setContentPane(contentPane);	
	}

	public void actionPerformed(ActionEvent event)
	{
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		if (event.getSource() == encryptButton)
		{
			// take the message in the first JTextArea, use the passphrase, and invoke the bouncycastle AES implementation to encrypt.
			try {
		        ciphertextArea.setText(encrypt(passphraseField.getText(), messageArea.getText()).toString());				
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}

		else if (event.getSource() == decryptButton)
		{
			// take the ciphertext in the second JTextArea, use the passphrase, and invoke the bouncycastle AES implementation to decrypt.
			try {
				decryptedArea.setText(decrypt(passphraseField.getText(), ciphertextArea.getText().getBytes()).toString());
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			
			// indicate to the user that the decryption worked as intended
			if (decryptedArea.getText().equals(messageArea.getText())) {
				successfulDecryption.setSelected(true);
			}
			else {
				successfulDecryption.setSelected(false);
			}
		}
	}
	
	private static byte [] encrypt(String passphrase, String plaintext) throws Exception {
        SecretKey key = generateKey(passphrase);

        Cipher cipher = Cipher.getInstance("AES/CTR/NOPADDING");
        cipher.init(Cipher.ENCRYPT_MODE, key, generateIV(cipher), random);
        return cipher.doFinal(plaintext.getBytes());
    }

    private static String decrypt(String passphrase, byte [] ciphertext) throws Exception {
        SecretKey key = generateKey(passphrase);

        Cipher cipher = Cipher.getInstance("AES/CTR/NOPADDING");
        cipher.init(Cipher.DECRYPT_MODE, key, generateIV(cipher), random);
        return new String(cipher.doFinal(ciphertext));
    }

    private static SecretKey generateKey(String passphrase) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(passphrase.toCharArray(), salt.getBytes(), iterations, keyLength);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWITHSHA256AND256BITAES-CBC-BC");
        return keyFactory.generateSecret(keySpec);
    }

    private static IvParameterSpec generateIV(Cipher cipher) throws Exception {
        byte [] ivBytes = new byte[cipher.getBlockSize()];
        random.nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }


}