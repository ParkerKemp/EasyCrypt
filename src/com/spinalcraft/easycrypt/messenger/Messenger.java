package com.spinalcraft.easycrypt.messenger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.apache.commons.lang3.StringEscapeUtils;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.spinalcraft.easycrypt.EasyCrypt;

public abstract class Messenger {
	public static boolean shouldShowDebug = false;
	private String message;
	
	private HashMap<String, String> headers;
	private HashMap<String, String> items;
	
	private boolean needsSecretKey = false;
	private String lockedBody;
	
	public Messenger(){
		items = new HashMap<String, String>();
		headers = new HashMap<String, String>();
	}
	
	public String getMessage(){
		return message;
	}
	
	protected void addItem(String key, String item){
		items.put(key, item);
	}
	
	protected void addHeader(String key, String header){
		headers.put(key, header);
	}
	
	protected String getItem(String key){
		return items.get(key);
	}
	
	protected String getHeader(String key){
		return headers.get(key);
	}
	
	protected boolean needsSecretKey(){
		return needsSecretKey;
	}
	
	protected void sendMessage(PrintStream printer){
		message = "";
		
		message += getHeaderSection();
		message += getItemSection();
		
		printer.print(message);
		if(shouldShowDebug){
			System.out.println("Sent Message: " + message);
		}
	}
	
	protected void sendEncrypted(PrintStream printer, SecretKey secretKey, EasyCrypt crypt){
		headers.put("encrypted", "1");

		message = "";
		message += getHeaderSection();
		message += getEncryptedBody(secretKey, crypt);
		
		printer.print(message);
		System.out.println("Sent Message: " + message);
	}
	
	protected void receiveMessage(BufferedReader reader){
		message = "";
		String line = "";
		try {
			parseHeaderSection(reader);
			if(headers.containsKey("encrypted") && headers.get("encrypted").equals("1")){
				lockedBody = reader.readLine();
				needsSecretKey = true;
			}
			else{
				parseItemSection(reader);
			}
		} catch (NumberFormatException e){
			System.out.println("Invalid message header: " + line);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		if(shouldShowDebug){
			System.out.println("Received Message: " + message);
		}
	}
	
	protected void decrypt(SecretKey secretKey, EasyCrypt crypt){
		parseEncryptedBody(secretKey, crypt);
	}
	
	private String getHeaderSection(){
		String headerSection = "";
		headerSection += headers.size() + "\n";
		for(String key : headers.keySet()){
			headerSection += key + ":" + StringEscapeUtils.escapeJava(headers.get(key)) + "\n";
		}
		return headerSection;
	}
	
	private String getItemSection(){
		String itemSection = "";
		itemSection += items.size() + "\n";
		for(String key : items.keySet()){
			itemSection += key + ":" + StringEscapeUtils.escapeJava(items.get(key)) + "\n";
		}
		return itemSection;
	}
	
	private String getEncryptedBody(SecretKey secretKey, EasyCrypt crypt){
		JsonObject obj = new JsonObject();
		for(String key : items.keySet()){
			obj.addProperty(key, StringEscapeUtils.escapeJava(items.get(key)));
		}
		return crypt.encode(crypt.encryptMessage(secretKey, obj.toString())) + "\n";
	}
	
	private void parseHeaderSection(BufferedReader reader) throws IOException{
		String line = reader.readLine();
		message += line + "\n";
		int numHeaders = Integer.parseInt(line);
		
		for(int i = 0; i < numHeaders; i++){
			line = reader.readLine();
			message += line + "\n";
			String tokens[] = line.split(":");
			headers.put(tokens[0], StringEscapeUtils.unescapeJava(tokens[1]));
		}
	}
	
	private void parseItemSection(BufferedReader reader) throws IOException{
		String line = reader.readLine();
		message += line + "\n";
		int numItems = Integer.parseInt(line);
		
		for(int i = 0; i < numItems; i++){
			line = reader.readLine();
			message += line + "\n";
			String tokens[] = line.split(":");
			items.put(tokens[0], StringEscapeUtils.unescapeJava(tokens[1]));
		}
	}
	
	private void parseEncryptedBody(SecretKey secretKey, EasyCrypt crypt){
		message += lockedBody;
		String json = crypt.decryptMessage(secretKey, crypt.decode(lockedBody));
		JsonParser parser = new JsonParser();
		JsonObject obj = parser.parse(json).getAsJsonObject();
		for(Map.Entry<String, JsonElement> entry : obj.entrySet()){
			items.put(entry.getKey(), entry.getValue().getAsString());
		}
		needsSecretKey = false;
	}
}
