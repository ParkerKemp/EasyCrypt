package com.spinalcraft.easycrypt;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public abstract class EasyCrypt {
	public static final int RSA = 0, AES = 1;
	public static final int EncryptionStrength = 1024;
	
	public KeyPair generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(EncryptionStrength);
        return generator.generateKeyPair();
    }
	
	public SecretKey generateSecretKey() throws NoSuchAlgorithmException{
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		return generator.generateKey();
	}

    public PrivateKey loadPrivateKey(String key64) throws GeneralSecurityException {
        byte[] clear = decode(key64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey priv = fact.generatePrivate(keySpec);
        Arrays.fill(clear, (byte) 0);
        return priv;
    }

    public PublicKey loadPublicKey(String key64) throws GeneralSecurityException {
        byte[] data = decode(key64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(spec);
    }
    
    public SecretKey loadSecretKey(String str){
    	byte[] data = decode(str);
    	return new SecretKeySpec(data, "AES");
    }

    public String stringFromPrivateKey(PrivateKey priv) throws GeneralSecurityException {
//        KeyFactory fact = KeyFactory.getInstance("RSA");
//        PKCS8EncodedKeySpec spec = fact.getKeySpec(priv, PKCS8EncodedKeySpec.class);
        byte[] packed = priv.getEncoded();
        String key64 = encode(packed);

        Arrays.fill(packed, (byte) 0);
        return key64;
    }

    public String stringFromPublicKey(PublicKey publ) throws GeneralSecurityException {
//        KeyFactory fact = KeyFactory.getInstance("RSA");
//        X509EncodedKeySpec spec = fact.getKeySpec(publ, X509EncodedKeySpec.class);
        return encode(publ.getEncoded());
    }
    
    public String stringFromSecretKey(SecretKey secret){
    	byte[] packed = secret.getEncoded();
    	String key64 = encode(packed);
    	
    	Arrays.fill(packed, (byte) 0);
    	return key64;
    }
    
    public byte[] encryptMessage(SecretKey key, String plaintext){
        Cipher cipher;
		try {
			cipher = Cipher.getInstance(getAlgorithm(AES));
	        cipher.init(Cipher.ENCRYPT_MODE, key);
	        IvParameterSpec spec = cipher.getParameters().getParameterSpec(IvParameterSpec.class);
	        byte[] iv = spec.getIV();
	        return concat(iv, cipher.doFinal(plaintext.getBytes()));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			e.printStackTrace();
		}
		return null;
    }

    public String decryptMessage(SecretKey key, byte[] ciphertext) {
        Cipher cipher;
        byte[] iv = Arrays.copyOfRange(ciphertext, 0, 16);
        System.out.println("IV: " + new String(iv));
        byte[] encrypted = Arrays.copyOfRange(ciphertext, 16, ciphertext.length);
		try {
			IvParameterSpec initializationVector = new IvParameterSpec(iv);
			cipher = Cipher.getInstance(getAlgorithm(AES));
			cipher.init(Cipher.DECRYPT_MODE, key, initializationVector);
	        return new String(cipher.doFinal(encrypted));
	    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
        return null;
    }
    
    public byte[] encryptKey(PublicKey pub, SecretKey secret){
    	Cipher cipher;
    	try {
    		cipher = Cipher.getInstance(getAlgorithm(RSA));
        	cipher.init(Cipher.ENCRYPT_MODE, pub);
        	return cipher.doFinal(secret.getEncoded());
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
    	return null;
    }
    
    public SecretKey decryptKey(PrivateKey priv, byte[] keyCipher){
    	Cipher cipher;
    	try {
			cipher = Cipher.getInstance(getAlgorithm(RSA));
			cipher.init(Cipher.DECRYPT_MODE, priv);
			byte[] decrypted = cipher.doFinal(keyCipher);
			return new SecretKeySpec(decrypted, "AES");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
    	return null;
    }
    
    public abstract String encode(byte[] bytes);
    
    public abstract byte[] decode(String str);
    
	private byte[] concat(byte[] a, byte[] b) {
		int aLen = a.length;
		int bLen = b.length;
		byte[] c = new byte[aLen + bLen];
		System.arraycopy(a, 0, c, 0, aLen);
		System.arraycopy(b, 0, c, aLen, bLen);
		return c;
	}

    private String getAlgorithm(int algo){
    	switch(algo){
    	case RSA:
    		return "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
    	case AES:
    		return "AES/CFB8/NoPadding";//"AES/CBC/PKCS5Padding";
    	default:
    		return "AES/CBC/PKCS5Padding";
    	}
    }
}
