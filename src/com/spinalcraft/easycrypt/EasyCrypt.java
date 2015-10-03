package com.spinalcraft.easycrypt;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public abstract class EasyCrypt {
	public static enum Algorithm {RSA, AES};
	
	public KeyPair generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        generator.initialize(1024, random);
        return generator.generateKeyPair();
    }

    public PrivateKey loadPrivateKey(String key64) throws GeneralSecurityException {
        byte[] clear = decode(key64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey priv = fact.generatePrivate(keySpec);
        Arrays.fill(clear, (byte) 0);
        return priv;
    }

    public PublicKey loadPublicKey(String stored) throws GeneralSecurityException {
        byte[] data = decode(stored);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(spec);
    }

    public String stringFromPrivateKey(PrivateKey priv) throws GeneralSecurityException {
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = fact.getKeySpec(priv, PKCS8EncodedKeySpec.class);
        byte[] packed = spec.getEncoded();
        String key64 = encode(packed);

        Arrays.fill(packed, (byte) 0);
        return key64;
    }

    public String stringFromPublicKey(PublicKey publ) throws GeneralSecurityException {
        KeyFactory fact = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec spec = fact.getKeySpec(publ, X509EncodedKeySpec.class);
        return encode(spec.getEncoded());
    }
    
    public String encrypt(PublicKey key, String plaintext, Algorithm algorithm){
        Cipher cipher;
		try {
			cipher = Cipher.getInstance(getAlgorithm(algorithm));
	        cipher.init(Cipher.ENCRYPT_MODE, key);
	        return new String(cipher.doFinal(plaintext.getBytes()));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		}
		return null;
    }

    public String decrypt(PrivateKey key, String ciphertext, Algorithm algorithm) {
        Cipher cipher;
		try {
			cipher = Cipher.getInstance(getAlgorithm(algorithm));
			cipher.init(Cipher.DECRYPT_MODE, key);
	        return new String(cipher.doFinal(ciphertext.getBytes()));
	    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
        return null;
    }
    
    protected abstract byte[] decode(String str);
    
    protected abstract String encode(byte[] bytes);
    
    private String getAlgorithm(Algorithm algo){
    	switch(algo){
    	case RSA:
    		return "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
    	case AES:
    		return "AES/CBC/PKCS5Padding";
    	default:
    		return "AES/CBC/PKCS5Padding";
    	}
    }
}
