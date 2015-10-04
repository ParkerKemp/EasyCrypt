package com.spinalcraft.easycrypt.messenger;

import java.io.BufferedReader;

public class MessageReceiver extends Messenger{
	private BufferedReader reader;
	public MessageReceiver(BufferedReader reader){
		this.reader = reader;
	}
	
	@Override
	public String get(String key){
		return super.get(key);
	}
	
	public void receiveMessage(){
		super.receiveMessage(reader);
	}
}
