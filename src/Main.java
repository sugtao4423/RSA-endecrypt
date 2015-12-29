import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class Main{

	private static final String PRIVATE_KEY_FILE = "/Users/tao/Desktop/der/private_key.der";
	private static final String PUBLIC_KEY_FILE = "/Users/tao/Desktop/der/public_key.der";

	public static void main(String[] args) throws Exception{
		String encrypt = encrypt("test");
		String decript = decrypt(encrypt);
		System.out.println(encrypt);
		System.out.println(decript);
	}

	public static String encrypt(String text) throws Exception{
		File keyFile = new File(PUBLIC_KEY_FILE);
		byte[] encodedKey = new byte[(int)keyFile.length()];

		FileInputStream fis = new FileInputStream(keyFile);
		fis.read(encodedKey);
		fis.close();

		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);

		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pubKey = kf.generatePublic(publicKeySpec);

		Cipher rsa = Cipher.getInstance("RSA");
		rsa.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] cipherText = rsa.doFinal(text.getBytes());
		return Base64.getEncoder().encodeToString(cipherText);
	}
	
	public static String decrypt(String base64Text) throws Exception{
		byte[] texts = Base64.getDecoder().decode(base64Text);
		
		File keyFile = new File(PRIVATE_KEY_FILE);
		byte[] encodedKey = new byte[(int)keyFile.length()];
		
		FileInputStream fis = new FileInputStream(keyFile);
		fis.read(encodedKey);
		fis.close();

		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

		Cipher rsa = Cipher.getInstance("RSA");
		rsa.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] plainText = rsa.doFinal(texts);
		return new String(plainText);
	}
}
