import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DigestGuts {
    protected byte[] messageDigest(String message, String whichDigest) throws NoSuchAlgorithmException {
		// creates a digest of the current message
		MessageDigest sha = MessageDigest.getInstance(whichDigest);
		sha.update(message.getBytes());
		return sha.digest();        
	}
}
