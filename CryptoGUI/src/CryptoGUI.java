import java.awt.Color;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
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
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class CryptoGUI extends JFrame implements ActionListener
{
	private JTextField passphraseField;
    private JTextArea messageArea, ciphertextArea, decryptedArea;
    private JButton decryptButton, encryptButton;
    private ButtonGroup keyLength;
    private JCheckBox successfulDecryption;
    
    private CryptoGuts cg;
    private String passphrase = "", message = "";
    public CryptoGUI()
    {
            // Set up the outer window
            super("CryptoGUI");
                        
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setSize(375, 800);
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
            
            // Encrypt button
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
    
	public void actionPerformed(ActionEvent event) {
		
		int keylenchoice;
		
        if (event.getSource() == encryptButton) {
        	cg = new CryptoGuts();
        	passphrase = passphraseField.getText();
        	message = messageArea.getText();
        	keylenchoice = Integer.parseInt(keyLength.getSelection().getActionCommand());
        	
			try {
				if (passphrase.equals("") || message.equals("")) {
        			JOptionPane.showMessageDialog(this,"No current passphrase or message entered. Please enter a passphrase and message, and then press 'Encrypt' again.", "noPassOrMessage", JOptionPane.ERROR_MESSAGE);
        		}
				else {
					cg.encrypt(passphrase, message, keylenchoice);
					this.ciphertextArea.setText(hexConverter.toHex(cg.ciphertext.getCiphertextByteArr()));
				}
			} catch (InvalidKeyException | NumberFormatException
					| InvalidAlgorithmParameterException
					| IllegalBlockSizeException | BadPaddingException
					| UnsupportedEncodingException | NoSuchAlgorithmException | NullPointerException e) {
				e.printStackTrace();
			} catch (wrongKeyLengthException e) {
				JOptionPane.showMessageDialog(this,"Cannot use this key length!", "wrongKeyLength", JOptionPane.ERROR_MESSAGE);
				//e.printStackTrace();
			} catch (passphraseTooLargeException e) {
				JOptionPane.showMessageDialog(this,"Passphrase too large!", "passphraseTooLarge", JOptionPane.ERROR_MESSAGE);
				//e.printStackTrace();
			}
        }
        
        // if this is pressed first, needs to e greyed outy. if pass or mess changed then need to grey out again until enc pressed
        else if (event.getSource() == decryptButton) {
        	try {
        		if (!cg.ciphertext.equals(null)) { // WTF IS GOING ON HERE.
        			if (!passphraseField.getText().equals(passphrase) || !messageArea.getText().equals(message)) {
            			JOptionPane.showMessageDialog(this,"I believe you have changed the passphrase or message without re-encrypting. Please press 'Encrypt' again.", "needToEncrypt", JOptionPane.ERROR_MESSAGE);
            		}
            		else {
            			decryptedArea.setText(cg.decrypt(cg.ciphertext));
            		}
        		} 
        		else {
        			JOptionPane.showMessageDialog(this,"No current ciphertext to decrypt. Please enter a passphrase and message, and then press 'Encrypt'.", "noCiphertext", JOptionPane.ERROR_MESSAGE);
        		}
			} catch (InvalidKeyException | InvalidAlgorithmParameterException
					| IllegalBlockSizeException | BadPaddingException e) {
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

	public static void main(String[] args) {
		if (args.length == 0) {
			CryptoGUI app = new CryptoGUI();
		}
		else if (args.length < 5){
			System.err.print("Invalid number of parameters. Please input the passphrase (string), key length (int),\n"
					+"whether or not you're asking to encrypt a file on your drive (1) or a string (0),\nand then"+
					" either the location of the file to encrypt(string of the form C:\\[stuff]) \nor your plaintext (string).");
		}
		else if (args.length > 6) {
			System.err.print("Invalid number of parameters. Please input the passphrase (string), key length (int),\n"
					+"whether or not you're asking to encrypt a file on your drive (1) or a string (0),\n"+
					" either the location of the file to encrypt(string of the form C:\\[stuff]) \nor your plaintext (string),"
					+ "and then, unless you want stuff spit out to the command line, the desired location for the ciphertext (string of the form C:\\[stuff]).");
		}
		else {
			CryptoCommandLine cl = new CryptoCommandLine(args);
		}
	}
}