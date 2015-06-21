package my.benchmark.group;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AESDemo {
	
	private static final String password = "test";
    private static String salt;
    private static int pswdIterations = 65536  ;
    private static int keySize = 256;
    
    public String encoded;
    public SecretKeySpec secret;
    
    public AESDemo() {
    	//get salt
        salt = generateSalt();      
        byte[] saltBytes;
		try {
			saltBytes = salt.getBytes("UTF-8");
			// Derive the key
	        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	        PBEKeySpec spec = new PBEKeySpec(
	                password.toCharArray(), 
	                saltBytes, 
	                pswdIterations, 
	                keySize
	                );
	 
	        SecretKey secretKey = factory.generateSecret(spec);
	        secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
	        encoded = new String(Base64.encodeBase64(secretKey.getEncoded()));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
 
    public String encrypt(String plainText) throws Exception {
        //encrypt the message
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        byte[] encryptedTextBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        return new String(Base64.encodeBase64(encryptedTextBytes));
    }
 
    public String decrypt(String encryptedText) throws Exception {
        byte[] encryptedTextBytes = Base64.decodeBase64(encryptedText);
 
        byte[] decoded = Base64.decodeBase64(encoded);
        SecretKeySpec secret = new SecretKeySpec(decoded, "AES");
 
        // Decrypt the message
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secret);
     
 
        byte[] decryptedTextBytes = null;
        try {
            decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
 
        return new String(decryptedTextBytes);
    }
 
    public String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[20];
        random.nextBytes(bytes);
        String s = new String(bytes);
        return s;
    }

}