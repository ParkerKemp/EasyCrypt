package com.spinalcraft.easycrypt;

import java.security.GeneralSecurityException;
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

public abstract class EasyCrypt {
	public KeyPair generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        generator.initialize(1024, random);
        return generator.generateKeyPair();
    }

    public PrivateKey loadPrivateKey(String key64) throws GeneralSecurityException {
        byte[] clear = decode(key64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
        KeyFactory fact = KeyFactory.getInstance("DSA");
        PrivateKey priv = fact.generatePrivate(keySpec);
        Arrays.fill(clear, (byte) 0);
        return priv;
    }

    public PublicKey loadPublicKey(String stored) throws GeneralSecurityException {
        byte[] data = decode(stored);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("DSA");
        return fact.generatePublic(spec);
    }

    public String stringFromPrivateKey(PrivateKey priv) throws GeneralSecurityException {
        KeyFactory fact = KeyFactory.getInstance("DSA");
        PKCS8EncodedKeySpec spec = fact.getKeySpec(priv,
                PKCS8EncodedKeySpec.class);
        byte[] packed = spec.getEncoded();
        String key64 = encode(packed);

        Arrays.fill(packed, (byte) 0);
        return key64;
    }

    public String stringFromPublicKey(PublicKey publ) throws GeneralSecurityException {

        KeyFactory fact = KeyFactory.getInstance("DSA");
        X509EncodedKeySpec spec = fact.getKeySpec(publ,
                X509EncodedKeySpec.class);
        return encode(spec.getEncoded());
    }
    
    protected abstract byte[] decode(String str);
    
    protected abstract String encode(byte[] bytes);
}
