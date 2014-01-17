import java.awt.Color;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;


public class CryptoGUI extends JFrame implements ActionListener
{
    // Need to maintain byte array of ciphertext so that padding will be maintained 
    private byte[] ciphertext;

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
		messageArea.setLineWrap(true);
        messageArea.setWrapStyleWord(true);
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
		ciphertextArea.setLineWrap(true);
        ciphertextArea.setWrapStyleWord(true);
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
		decryptedArea.setLineWrap(true);
        decryptedArea.setWrapStyleWord(true);
		decryptedArea.setEditable(false);
		decryptedPanel.add(decryptedArea);
		contentPane.add(decryptedPanel);
		
		// Is the decrypted message the same as the original message?
		JPanel successfulDecryptionPanel = new JPanel();
		successfulDecryptionPanel.add(new JLabel("Is the decrypted message the same as the original?"));
		successfulDecryption = new JCheckBox();
		successfulDecryption.setSelected(false);
		successfulDecryption.setEnabled(false);
        successfulDecryptionPanel.add(successfulDecryption);
		contentPane.add(successfulDecryptionPanel);
		
		// Make the main window show the updated content pane
		setContentPane(contentPane);	
	}

	public void actionPerformed(ActionEvent event)
	{
		// creates a cipher object with SunJCE
		Cipher cipher = null;
		SecretKeySpec key = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
	        key = new SecretKeySpec(hexStringToByteArray(passphraseField.getText()), "AES");
	        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[cipher.getBlockSize()]));
	        
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		if (event.getSource() == encryptButton)
		{		
			try {
				ciphertext = cipher.doFinal(messageArea.getText().getBytes());
				ciphertextArea.setText(ciphertext.toString());
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		else if (event.getSource() == decryptButton)
		{
	        try {
				cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[cipher.getBlockSize()]));
				String plainText = new String(cipher.doFinal(ciphertext));
		        decryptedArea.setText(plainText);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
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
	
	public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
	
	/*private static byte [] encrypt(String passphrase, String plaintext) throws Exception {
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
    }*/


}