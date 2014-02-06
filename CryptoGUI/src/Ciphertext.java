import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Ciphertext {
	private AlgorithmParameterSpec ivspec;
	private SecretKeySpec key;
    private byte[] ciphertext; // Need to maintain byte array of ciphertext so that padding will be maintained
    
	protected void setKey(SecretKeySpec generatedKey) {
		this.key = generatedKey;
	}

	protected void setIVspec(IvParameterSpec ivParameterSpec) {
		this.ivspec = ivParameterSpec;
	}

	protected void setCiphertextByteArr(byte[] ciphertext) {
		this.ciphertext = ciphertext;
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
}
