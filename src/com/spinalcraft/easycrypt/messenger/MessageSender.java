package com.spinalcraft.easycrypt.messenger;

import java.io.IOException;
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
	public void setIdentifier(String id){
		super.setIdentifier(id);
	}
	
	@Override
	public void addHeader(String key, String header){
		super.addHeader(key, header);
	}
	
	@Override
	public void sendMessage() {
		super.sendMessage();
	};
	
	@Override
	public boolean sendEncrypted(SecretKey secretKey) throws IOException{
		return super.sendEncrypted(secretKey);
	}

	@Override
	protected SecretKey getSecretKeyForIdentifier(String identifier){
		return null;
	}

	@Override
	protected long getLastTransmitTimeForIdentifier(String identifier) {
		return 0;
	}
}
