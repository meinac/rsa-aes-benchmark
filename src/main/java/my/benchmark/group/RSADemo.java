package my.benchmark.group;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

public class RSADemo {
	
	public Key publicKey;
	public Key privateKey;
	
	public RSADemo() {
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1024);
			KeyPair kp = kpg.genKeyPair();
			publicKey = kp.getPublic();
	        privateKey = kp.getPrivate();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	public String encrypt(String text) {
		try {            
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherData = cipher.doFinal(text.getBytes());
            byte[] encodedBytes = Base64.encodeBase64(cipherData);
            return new String(encodedBytes);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public String decrypt(String text) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] newCipherData = cipher.doFinal(Base64.decodeBase64(text));
			return new String(newCipherData);
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}
	}

}