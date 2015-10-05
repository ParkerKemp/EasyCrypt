package com.spinalcraft.easycrypt.messenger;

import java.io.BufferedReader;

import javax.crypto.SecretKey;

import com.spinalcraft.easycrypt.EasyCrypt;

public class MessageReceiver extends Messenger{
	private BufferedReader reader;
	public MessageReceiver(BufferedReader reader){
		this.reader = reader;
	}
	
	@Override
	public String getItem(String key){
		return super.getItem(key);
	}
	
	@Override
	public String getHeader(String key){
		return super.getHeader(key);
	}
	
	@Override
	public boolean needsSecretKey(){
		return super.needsSecretKey();
	}
	
	public void receiveMessage(){
		super.receiveMessage(reader);
	}
	
	@Override
	public void decrypt(SecretKey secretKey, EasyCrypt crypt){
		super.decrypt(secretKey, crypt);
	}
}
