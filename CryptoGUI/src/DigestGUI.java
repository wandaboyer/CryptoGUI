import java.awt.Color;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;


public class DigestGUI extends JFrame implements ActionListener {
    private JTextArea messageArea, digestArea;
    private JButton digestButton;
    private ButtonGroup whichDigest;
    
    private DigestGuts dg;
    
    public DigestGUI()
    {
        // Set up the outer window
        super("DigestGUI");
                    
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(375, 475);
        setLocation(500,0);
        setResizable(false);
        setVisible(true);
        
        // Set up the content area
        Container contentPane = getContentPane();
        contentPane.setBackground(Color.WHITE);                
        FlowLayout layoutMgr = new FlowLayout(FlowLayout.LEFT);
        contentPane.setLayout(layoutMgr);

        // Input message to create digest of
        JPanel messagePanel = new JPanel();
        messagePanel.add(new JLabel("Enter message:"));
        messageArea = new JTextArea("", 10, 15);
        messageArea.setLineWrap(true);
        messageArea.setWrapStyleWord(true);
        messagePanel.add(messageArea);
        contentPane.add(messagePanel);
        
        // Choose desired digest algorithm
		whichDigest = new ButtonGroup();
		JPanel whichDigestPanel = new JPanel();
		JLabel keyLengthQ = new JLabel("What digest algorithm?");
		whichDigestPanel.add(keyLengthQ);
		whichDigestPanel.setBackground(Color.WHITE);
		whichDigestPanel.setLayout(new FlowLayout());
		JRadioButton rb = new JRadioButton("SHA-256",true);
		rb.setBackground(Color.WHITE);
		rb.setActionCommand("SHA-256");
		whichDigest.add(rb);
		whichDigestPanel.add(rb);
		rb = new JRadioButton("SHA-512");
		rb.setBackground(Color.WHITE);
		rb.setActionCommand("SHA-512");
		whichDigest.add(rb);
		whichDigestPanel.add(rb);
		rb = new JRadioButton("MD5", true);
		rb.setBackground(Color.WHITE);
		rb.setActionCommand("MD5");
		whichDigest.add(rb);
		whichDigestPanel.add(rb);
		contentPane.add(whichDigestPanel);

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
        
        // Make the main window show the updated content pane
        setContentPane(contentPane);        
    }
    
	public void actionPerformed(ActionEvent event) {
		String digestChoice;
        if (event.getSource() == digestButton) {
        	dg = new DigestGuts();
        	if (messageArea.getText().equals("")) {
    			JOptionPane.showMessageDialog(this,"No current passphrase or message entered. Please enter a passphrase and message, and then press 'Encrypt' again.", "noPassOrMessage", JOptionPane.ERROR_MESSAGE);
    		}
			else {
				digestChoice = whichDigest.getSelection().getActionCommand();
				this.digestArea.setText(hexConverter.toHex(dg.messageDigest(messageArea.getText(), digestChoice)));
			}
        }
    }
	
	public static void main(String[] args){
       	DigestGUI app = new DigestGUI();
 	}
}
