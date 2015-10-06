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
	
	private static long authExpire = 300;
	private static long lastSent = 0;
	
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
	
	public static void setAuthExpiration(int expiration){
		authExpire = expiration;
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
		if(shouldSendHandshake() && !sendHandshakeRequest(secretKey))
			return false;
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
		message = "";
		String line = "";
		try {
			parseHeaderSection();
			String identifier = headers.get("id");
			SecretKey secretKey = getSecretKeyForIdentifier(identifier);
			if(headers.containsKey("encrypted") && headers.get("encrypted").equals("1")){
				if(secretKey == null)
					return false;
				parseEncryptedBody(getSecretKeyForIdentifier(identifier));
			}
			else if(headers.containsKey("handshake") && headers.get("handshake").equals("1")){
				if(secretKey == null)
					return false;
				if(parseHandshakeRequest(getSecretKeyForIdentifier(identifier), getLastTransmitTimeForIdentifier(identifier))){
					return receiveMessage();
				}
				else{
					return false;
				}
			}
			else{
				parseItemSection();
			}
			return true;
		} catch (NumberFormatException e){
			System.out.println("Invalid message header: " + line);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		if(shouldShowDebug){
			System.out.println("Received Message: " + message);
		}
		return false;
	}
	
	protected abstract SecretKey getSecretKeyForIdentifier(String identifier);
	
	protected abstract long getLastTransmitTimeForIdentifier(String identifier);
	
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
			headers.put(tokens[0], StringEscapeUtils.unescapeJava(tokens[1]));
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
			items.put(tokens[0], StringEscapeUtils.unescapeJava(tokens[1]));
		}
	}
	
	private void parseEncryptedBody(SecretKey secretKey) throws IOException{
		String body = reader.readLine();
		message += body;
		String json = crypt.decryptMessage(secretKey, crypt.decode(body));
		JsonParser parser = new JsonParser();
		JsonObject obj = parser.parse(json).getAsJsonObject();
		for(Map.Entry<String, JsonElement> entry : obj.entrySet()){
			items.put(entry.getKey(), entry.getValue().getAsString());
		}
	}
	
	private boolean shouldSendHandshake(){
		return (System.currentTimeMillis() / 1000) - lastSent > authExpire;
	}
	
	private boolean sendHandshakeRequest(SecretKey secretKey) throws IOException{
		long timestamp = System.currentTimeMillis() / 1000;
		String handshake = "";
		handshake += "2\nhandshake:1\nid:" + headers.get("id") + "\n";
		JsonObject obj = new JsonObject();
		obj.addProperty("id", headers.get("id"));
		obj.addProperty("timestamp", timestamp);
		handshake += crypt.encode(crypt.encryptMessage(secretKey, obj.toString())) + "\n";
		printer.print(handshake);
		if(shouldShowDebug){
			System.out.println("Sending handshake request: " + handshake);
		}
		
		return receiveHandshakeResponse(secretKey, timestamp);
	}
	
	private boolean parseHandshakeRequest(SecretKey secretKey, long lastTransmit) throws IOException{
		String request = reader.readLine();
		if(shouldShowDebug){
			System.out.println("Received handshake request: " + request);
		}
		String json = crypt.decryptMessage(secretKey, crypt.decode(request));
		JsonParser parser = new JsonParser();
		JsonObject obj = parser.parse(json).getAsJsonObject();
		long timestamp = obj.get("timestamp").getAsLong();
		if(timestamp <= lastTransmit || lastTransmit == -1){
			return false;
		}
		sendHandshakeResponse(secretKey, obj.get("timestamp").getAsLong());
		return true;
	}
	
	private void sendHandshakeResponse(SecretKey secretKey, long timestamp){
		JsonObject obj = new JsonObject();
		obj.addProperty("Hello", "Goodbye");
		obj.addProperty("timestamp", timestamp);
		String response = crypt.encode(crypt.encryptMessage(secretKey, obj.toString())) + "\n";
		printer.print(response);
		if(shouldShowDebug){
			System.out.println("Sending handshake response: " + response);
		}
	}
	
	private boolean receiveHandshakeResponse(SecretKey secretKey, long timestamp) throws IOException{
		String response = reader.readLine();
		if(shouldShowDebug){
			System.out.println("Received handshake response: " + response);
		}
		String json = crypt.decryptMessage(secretKey, crypt.decode(response));
		JsonParser parser= new JsonParser();
		JsonObject obj = parser.parse(json).getAsJsonObject();
		return obj.get("timestamp").getAsLong() == timestamp && obj.get("Hello").getAsString().equals("Goodbye");
	}
}
