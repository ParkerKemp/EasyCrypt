package com.spinalcraft.easycrypt.messenger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Socket;
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
	
	private EasyCrypt crypt;
	private BufferedReader reader;
	private PrintStream printer;
	
	public Messenger(Socket socket, EasyCrypt crypt){
		this.crypt = crypt;
		items = new HashMap<String, String>();
		headers = new HashMap<String, String>();
		try {
			reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			printer = new PrintStream(socket.getOutputStream());
		} catch (IOException e) {
			e.printStackTrace();
		}
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
	
	protected void setIdentifier(String id){
		headers.put("id", id);
	}
	
	protected String getItem(String key){
		return items.get(key);
	}
	
	protected String getHeader(String key){
		return headers.get(key);
	}
	
	protected void sendMessage(){
		message = "";
		
		message += getHeaderSection();
		message += getItemSection();
		
		printer.print(message);
		if(shouldShowDebug){
			System.out.println("Sent Message: " + message);
		}
	}
	
	protected boolean sendEncrypted(SecretKey secretKey) throws IOException{
		headers.put("encrypted", "1");

		message = "";
		message += getHeaderSection();
		message += getEncryptedBody(secretKey);
		
		printer.print(message);
		if(shouldShowDebug){
			System.out.println("Sent Message: " + message);
		}
		return true;
	}
	
	protected boolean receiveMessage(){
		return receiveMessage(null);
	}
	
	protected boolean receiveMessage(SecretKey secretKey){
		message = "";
		String line = "";
		try {
			parseHeaderSection();
			if(headers.containsKey("encrypted") && headers.get("encrypted").equals("1")){
				if(secretKey == null)
					return false;
				parseEncryptedBody(secretKey);
			}
			else{
				parseItemSection();
			}
		} catch (NumberFormatException e){
			System.out.println("Invalid message header: " + line);
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		
		if(shouldShowDebug){
			System.out.println("Received Message: " + message);
		}
		return true;
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
	
	private String getEncryptedBody(SecretKey secretKey){
		JsonObject obj = new JsonObject();
		for(String key : items.keySet()){
			obj.addProperty(key, StringEscapeUtils.escapeJava(items.get(key)));
		}
		return crypt.encode(crypt.encryptMessage(secretKey, obj.toString())) + "\n";
	}
	
	private void parseHeaderSection() throws IOException{
		String line = reader.readLine();
		message += line + "\n";
		int numHeaders = Integer.parseInt(line);
		
		for(int i = 0; i < numHeaders; i++){
			line = reader.readLine();
			message += line + "\n";
			String tokens[] = line.split(":");
			if(tokens.length == 2)
				headers.put(tokens[0], StringEscapeUtils.unescapeJava(tokens[1]));
			else if(tokens.length == 1)
				headers.put(tokens[0], null);
		}
	}
	
	private void parseItemSection() throws IOException{
		String line = reader.readLine();
		message += line + "\n";
		int numItems = Integer.parseInt(line);
		
		for(int i = 0; i < numItems; i++){
			line = reader.readLine();
			message += line + "\n";
			String tokens[] = line.split(":");
			if(tokens.length == 2)
				items.put(tokens[0], StringEscapeUtils.unescapeJava(tokens[1]));
			else if(tokens.length == 1)
				items.put(tokens[0], null);
		}
	}
	
	private void parseEncryptedBody(SecretKey secretKey) throws IOException{
		String body = reader.readLine();
		message += body;
		String json = crypt.decryptMessage(secretKey, crypt.decode(body));
		JsonParser parser = new JsonParser();
		JsonObject obj = parser.parse(json).getAsJsonObject();
		for(Map.Entry<String, JsonElement> entry : obj.entrySet()){
			items.put(entry.getKey(), StringEscapeUtils.unescapeJava(entry.getValue().getAsString()));
		}
	}
}
