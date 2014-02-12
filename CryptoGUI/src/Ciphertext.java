import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Base64;


public class Ciphertext {
	private AlgorithmParameterSpec ivspec;
	private SecretKeySpec key;
    private byte[] ciphertext; // Need to maintain byte array of ciphertext so that padding will be maintained
    //private byte[] base64encodedCiphertext;
    
    
	protected void setKey(SecretKeySpec generatedKey) {
		this.key = generatedKey;
	}

	protected void setIVspec(IvParameterSpec ivParameterSpec) {
		this.ivspec = ivParameterSpec;
	}

	protected void setCiphertextByteArr(byte[] ciphertext) {
		this.ciphertext = ciphertext;
		//this.base64encodedCiphertext = Base64.encode(ciphertext);
	}

	public Key getKey() {
		return this.key;
	}

	public AlgorithmParameterSpec getIVspec() {
		return this.ivspec;
	}

	public byte[] getCiphertextByteArr() {
		return this.ciphertext;
	}
	/*public byte[] getBase64EncodedCiphertext() {
		return this.base64encodedCiphertext;
	}*/
}
