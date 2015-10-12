package com.spinalcraft.easycrypt.messenger;

import java.net.Socket;

import javax.crypto.SecretKey;

import com.spinalcraft.easycrypt.EasyCrypt;

public abstract class MessageReceiver extends Messenger{

	public MessageReceiver(Socket socket, EasyCrypt crypt) {
		super(socket, crypt);
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
	public boolean receiveMessage(){
		return super.receiveMessage();
	}
	
	@Override
	public boolean receiveMessage(SecretKey secretKey){
		return super.receiveMessage(secretKey);
	}
}
