import java.awt.Color;
import java.awt.FlowLayout;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;


public class DigestGuts {
    private String message;
    private String digest;
    /*
    // Input message to encrypt
            JPanel messagePanel = new JPanel();
            messagePanel.add(new JLabel("Enter message to Encrypt:"));
            messageArea = new JTextArea("", 10, 15);
            messageArea.setLineWrap(true);
            messageArea.setWrapStyleWord(true);
            messagePanel.add(messageArea);
            contentPane.add(messagePanel);
    
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
    */
}
