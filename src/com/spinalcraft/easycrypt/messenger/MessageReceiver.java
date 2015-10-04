package com.spinalcraft.easycrypt.messenger;

import java.io.BufferedReader;

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
	
	public void receiveMessage(){
		super.receiveMessage(reader);
	}
}
