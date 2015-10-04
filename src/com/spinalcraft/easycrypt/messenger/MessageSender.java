package com.spinalcraft.easycrypt.messenger;

import java.io.PrintStream;

public class MessageSender extends Messenger{
	private PrintStream printer;
	public MessageSender(PrintStream printer){
		this.printer = printer;
	}
	
	@Override
	public void add(String key, String item){
		super.add(key, item);
	}
	
	public void sendMessage(){
		super.sendMessage(printer);
	}
}
