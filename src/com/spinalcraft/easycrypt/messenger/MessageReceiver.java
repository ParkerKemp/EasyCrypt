package com.spinalcraft.easycrypt.messenger;

import java.net.Socket;
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
	
	public void receiveMessage(){
		super.receiveMessage();
	}
}
