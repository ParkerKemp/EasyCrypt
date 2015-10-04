package com.spinalcraft.easycrypt.messenger;

import java.io.PrintStream;

import javax.crypto.SecretKey;

import com.spinalcraft.easycrypt.EasyCrypt;

public class MessageSender extends Messenger{
	private PrintStream printer;
	public MessageSender(PrintStream printer){
		this.printer = printer;
	}
	
	@Override
	public void addItem(String key, String item){
		super.addItem(key, item);
	}
	
	@Override
	public void addHeader(String key, String header){
		super.addHeader(key, header);
	}
	
	public void sendMessage(){
		super.sendMessage(printer);
	}
	
	public void sendEncrypted(SecretKey secretKey, EasyCrypt crypt){
		super.sendEncrypted(printer, secretKey, crypt);
	}
}
