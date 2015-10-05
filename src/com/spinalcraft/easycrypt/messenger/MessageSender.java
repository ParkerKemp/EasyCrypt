package com.spinalcraft.easycrypt.messenger;

import java.net.Socket;

import javax.crypto.SecretKey;
import com.spinalcraft.easycrypt.EasyCrypt;

public abstract class MessageSender extends Messenger{
	public MessageSender(Socket socket, EasyCrypt crypt){
		super(socket, crypt);
	}
	
	@Override
	public void addItem(String key, String item){
		super.addItem(key, item);
	}
	
	@Override
	public void addHeader(String key, String header){
		super.addHeader(key, header);
	}

	@Override
	protected SecretKey getSecretKeyForIdentifier(String identifier){
		return null;
	}
}
