package com.spinalcraft.easycrypt.messenger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintStream;
import java.util.HashMap;

import org.apache.commons.lang3.StringEscapeUtils;

public abstract class Messenger {
	public static boolean shouldShowDebug = false;
	private String message;
	
	private HashMap<String, String> items;
	
	public Messenger(){
		items = new HashMap<String, String>();
	}
	
	public String getMessage(){
		return message;
	}
	
	protected void add(String key, String item){
		items.put(key, item);
	}
	
	protected String get(String key){
		return items.get(key);
	}
	
	protected void sendMessage(PrintStream printer){
		message = "";
		message += items.size() + "\n";
		for(String key : items.keySet()){
			message += key + ":" + StringEscapeUtils.escapeJava(items.get(key)) + "\n";
		}
		
		printer.print(message);
		if(shouldShowDebug){
			System.out.println("Sent Message: " + message);
		}
	}
	
	protected void receiveMessage(BufferedReader reader){
		message = "";
		int numLines;
		try {
			String line = reader.readLine();
			message += line + "\n";
			numLines = Integer.parseInt(line);
			for(int i = 0; i < numLines; i++){
				line = reader.readLine();
				message += line + "\n";
				String tokens[] = line.split(":");
				items.put(tokens[0], StringEscapeUtils.unescapeJava(tokens[1]));
			}
		} catch (NumberFormatException | IOException e) {
			e.printStackTrace();
		}
		
		if(shouldShowDebug){
			System.out.println("Received Message: " + message);
		}
	}
}
