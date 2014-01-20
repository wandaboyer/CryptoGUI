import java.awt.Color;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
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

import javax.crypto.KeyGenerator;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ButtonGroup;
import javax.swing.ButtonModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class CryptoGUI extends JFrame implements ActionListener
{
    private JTextField passphraseField;
    private JTextArea messageArea, ciphertextArea, decryptedArea, digestArea;
    private JButton decryptButton, encryptButton, digestButton;
    private ButtonGroup keyLength;
    private JCheckBox successfulDecryption;
    
	private Cipher cipher;
	private String passphrase;
	private AlgorithmParameterSpec ivspec;
	private SecretKeySpec key;
    private String message;
    private String digest;
    private byte[] ciphertext; // Need to maintain byte array of ciphertext so that padding will be maintained
	
        
    public CryptoGUI()
    {
            // Set up the outer window
            super("CryptoGUI");
            Security.addProvider(new BouncyCastleProvider());
            // creates a cipher object with SunJCE
            try {
				this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			} catch (NoSuchAlgorithmException | NoSuchProviderException
					| NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setSize(375, 900);
            setLocation(500,0);
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
            passphrase = passphraseField.getText();
    		
            // Choose desired key length
    		keyLength = new ButtonGroup();
    		JPanel keyLengthPanel = new JPanel();
    		JLabel keyLengthQ = new JLabel("What length of key?");
    		keyLengthPanel.add(keyLengthQ);
    		keyLengthPanel.setBackground(Color.WHITE);
    		keyLengthPanel.setLayout(new FlowLayout());
    		JRadioButton rb = new JRadioButton("16 bytes",true);
    		rb.setBackground(Color.WHITE);
    		rb.setActionCommand("16");
    		keyLength.add(rb);
    		keyLengthPanel.add(rb);
    		rb = new JRadioButton("24 bytes");
    		rb.setBackground(Color.WHITE);
    		rb.setActionCommand("24");
    		keyLength.add(rb);
    		keyLengthPanel.add(rb);
    		rb = new JRadioButton("32 bytes", true);
    		rb.setBackground(Color.WHITE);
    		rb.setActionCommand("32");
    		keyLength.add(rb);
    		keyLengthPanel.add(rb);
    		passphrasePanel.add(keyLengthPanel);
    		contentPane.add(keyLengthPanel);
         
    		
            // Input message to encrypt
            JPanel messagePanel = new JPanel();
            messagePanel.add(new JLabel("Enter message to Encrypt:"));
            messageArea = new JTextArea("", 10, 15);
            messageArea.setLineWrap(true);
            messageArea.setWrapStyleWord(true);
            messagePanel.add(messageArea);
            contentPane.add(messagePanel);
            //message = messageArea.getText();
            
            // Encrypt button
            JPanel encryptPanel = new JPanel();
            encryptPanel.setBackground(Color.WHITE);
            encryptPanel.setLayout(new FlowLayout());
            encryptButton = new JButton("Encrypt");
            encryptButton.addActionListener(this);
            encryptPanel.add(encryptButton);
            contentPane.add(encryptPanel);
            
            // Digest button
            JPanel digestPanel = new JPanel();
            digestPanel.setBackground(Color.WHITE);
            digestPanel.setLayout(new FlowLayout());
            digestButton = new JButton("Compute message digest");
            digestButton.addActionListener(this);
            digestPanel.add(digestButton);
            //encryptPanel.add(digestButton);
            contentPane.add(digestPanel);
            
            // Resulting message digest
            JPanel digestAreaPanel = new JPanel();
            digestAreaPanel.add(new JLabel("Message digest:"));
            digestArea = new JTextArea("", 10, 15);
            digestArea.setLineWrap(true);
            digestArea.setWrapStyleWord(true);
            digestArea.setEditable(false);
            digestAreaPanel.add(digestArea);
            contentPane.add(digestAreaPanel);
            
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
        if (event.getSource() == encryptButton)
        {       
        	encrypt();
        }
        else if (event.getSource() == digestButton) {
        	messageDigest();
        }
        else if (event.getSource() == decryptButton)
        {
        	decrypt();
        }
    }

	private void messageDigest() {
		// creates a digest of the current message
		this.message = messageArea.getText();

		MessageDigest sha = null;
		try {
			//sha = MessageDigest.getInstance("MD5");
			sha = MessageDigest.getInstance("SHA-512");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        this.digest = toHex(sha.digest(this.message.getBytes()));
        this.digestArea.setText(this.digest);
	}

	private void encrypt() {
		this.passphrase = passphraseField.getText();
		generateKey();
		getIV();
		this.message = messageArea.getText();
		try {
			this.cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
            this.ciphertext = cipher.doFinal(message.getBytes());
            this.ciphertextArea.setText(toHex(ciphertext));
        } catch (IllegalBlockSizeException | BadPaddingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
        } catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private void decrypt() {
		try {
            this.cipher.init(Cipher.DECRYPT_MODE, this.key, this.ivspec);
            String plaintext = new String(this.cipher.doFinal(this.ciphertext));
            decryptedArea.setText(plaintext);
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

	private void generateKey() {
		/*Random r;
		byte[] salt = null;
        try {
        	// generate random salt
        	r = new SecureRandom();
			salt = new byte[16-this.passphrase.length()];
			r.nextBytes(salt);
            // make some kind of key from the passphrase field (needs to be 7 bytes), then pass to secretkeyspec
            byte[] morphedPassphrase = (this.passphrase+salt).getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            morphedPassphrase = sha.digest(morphedPassphrase);
            morphedPassphrase = Arrays.copyOf(morphedPassphrase, 16);
            key = new SecretKeySpec(morphedPassphrase, "AES");
            //cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
        
        } catch (NoSuchAlgorithmException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
        } catch (InvalidKeyException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
        }catch (UnsupportedEncodingException e) {
                // TODO Auto-generated catch block 
                e.printStackTrace();
        }	*/
		try {
			Random r;
			byte[] salt = null;
			// make some kind of key from the passphrase field (needs to be 7 bytes), then pass to secretkeyspec
			int keylenchoice = Integer.parseInt(keyLength.getSelection().getActionCommand());
			
			if (this.passphrase.length() < 16) {
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
			else if (this.passphrase.length() < 24) {
				if (keylenchoice == 16) {
					JOptionPane.showMessageDialog(this,"Cannot use this key length!", "wrongKeyLength", JOptionPane.ERROR_MESSAGE);
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
			else if (this.passphrase.length() <= 32) {
				if (keylenchoice == 16) {
					JOptionPane.showMessageDialog(this,"Cannot use this key length!", "wrongKeyLength", JOptionPane.ERROR_MESSAGE);
				}
				else if (keylenchoice == 24) {
					JOptionPane.showMessageDialog(this,"Cannot use this key length!", "wrongKeyLength", JOptionPane.ERROR_MESSAGE);
				}
				else if (keylenchoice == 32) {
					r = new SecureRandom();
					salt = new byte[32-passphrase.length()];
					r.nextBytes(salt);
				}
			}
			else {
				JOptionPane.showMessageDialog(this,"Choose a passphrase that is less than or equal to 32 bytes in length!", "passphraseTooLarge", JOptionPane.ERROR_MESSAGE);
			}
			
			byte[] morphedPassphrase = (passphrase+salt.toString()).getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			morphedPassphrase = sha.digest(morphedPassphrase);
			morphedPassphrase = Arrays.copyOf(morphedPassphrase, keylenchoice);
	        this.key = new SecretKeySpec(morphedPassphrase, "AES");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
		
	private void getIV () {
		byte[] iv = new byte[this.cipher.getBlockSize()];
		new SecureRandom().nextBytes(iv);
		this.ivspec = new IvParameterSpec(iv);
	}
 
	
	private static String toHex(String txt) {
        return toHex(txt.getBytes());
    }
    private static String fromHex(String hex) {
        return new String(toByte(hex));
    }

    private static byte[] toByte(String hexString) {
        int len = hexString.length()/2;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++)
            result[i] = Integer.valueOf(hexString.substring(2*i, 2*i+2), 16).byteValue();
        return result;
    }

    private static String toHex(byte[] buf) {
        if (buf == null)
            return "";
        StringBuffer result = new StringBuffer(2*buf.length);
        for (int i = 0; i < buf.length; i++) {
            appendHex(result, buf[i]);
        }
        return result.toString();
    }
	
    private final static String HEX = "0123456789ABCDEF";
    private static void appendHex(StringBuffer sb, byte b) {
        sb.append(HEX.charAt((b>>4)&0x0f)).append(HEX.charAt(b&0x0f));
    }
	
	public static void main(String[] args){
       	CryptoGUI app = new CryptoGUI();
 	}
}