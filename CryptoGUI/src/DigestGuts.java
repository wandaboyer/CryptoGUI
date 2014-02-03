import java.awt.Color;
import java.awt.FlowLayout;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;


public class DigestGuts {
    protected byte[] messageDigest(String message, String whichDigest) {
		// creates a digest of the current message

		MessageDigest sha = null;
		try {
			//sha = MessageDigest.getInstance("MD5");
			sha = MessageDigest.getInstance(whichDigest);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		sha.update(message.getBytes());
		return sha.digest();        
	}
}
