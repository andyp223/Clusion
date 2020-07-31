package org.crypto.sse;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.Collection;


import javax.crypto.NoSuchPaddingException;

import com.google.gson.Gson;
import com.google.common.base.Strings;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Iterators;
import com.google.common.collect.Multimap;
import com.google.common.collect.TreeMultimap;

// Multimap setup 

// update 

// query 

public class TestPhase2 {
	
	static int bigBlock = 1000;
	static int smallBlock = 100;
	
	public static void query_BIEX(IEX2Lev disj, Map<String, List<TokenDIS>> token) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
	NoSuchProviderException, NoSuchPaddingException, UnsupportedEncodingException, IOException {


int queryLength = 0;
int firstQueryLength = 0;

// determining the query length
for (String label : token.keySet()) {
	
	String[] values = label.split(" ");

	
	if (Integer.parseInt(values[0]) > queryLength) {
		queryLength = Integer.parseInt(values[0]);
	}
	
	if (Integer.parseInt(values[1]) > firstQueryLength) {
		firstQueryLength = Integer.parseInt(values[1]);
	}
	
}



Set<String> tmpBol = IEX2Lev.query(token.get(queryLength+" "+firstQueryLength), disj);


for (int i = 1; i < queryLength; i++) {
	Set<String> finalResult = new HashSet<String>();
	for (int k = 0; k < firstQueryLength; k++) {
		
		List<TokenDIS> tokenTMP = token.get(i+" "+k);

		if (!(tmpBol.size() == 0)) {
			List<Integer> temp = new ArrayList<Integer>(
					disj.getDictionaryForMM().get(new String(tokenTMP.get(0).getTokenDIC())));

			if (!(temp.size() == 0)) {
				int pos = temp.get(0);

				for (int j = 0; j < tokenTMP.get(0).getTokenMMLocal().size(); j++) {

					Set<String> temporary = new HashSet<String>();
					List<String> tempoList = RR2Lev.query(tokenTMP.get(0).getTokenMMLocal().get(j),
							disj.getLocalMultiMap()[pos].getDictionary(),
							disj.getLocalMultiMap()[pos].getArray());

					if (!(tempoList == null)) {
						temporary = new HashSet<String>(
								RR2Lev.query(tokenTMP.get(0).getTokenMMLocal().get(j),
										disj.getLocalMultiMap()[pos].getDictionary(),
										disj.getLocalMultiMap()[pos].getArray()));
					}

					finalResult.addAll(temporary);

					if (tmpBol.isEmpty()) {
						break;
					}

				}
			}

		}
	}
	tmpBol.retainAll(finalResult);			

}

Gson gson = new Gson();
System.out.println(gson.toJson(tmpBol));


}
	
	public static byte[] jsonToBytes(JSONArray obj) throws JSONException {
		byte[] output = new byte[obj.length()];
		for (int i = 0; i < obj.length(); i++) {
			output[i] = (byte)((int)obj.get(i));
		}
		return output;
		
	}
	
	public static Map<String,List<TokenDIS>> getTokens(JSONObject obj) throws JSONException {
		Map<String, List<TokenDIS>> token = new HashMap<String, List<TokenDIS>>();
		Iterator<String> keys = obj.keys();
		while(keys.hasNext()) {
			String key = keys.next();
			List<TokenDIS> tokenlist = new ArrayList<TokenDIS>();
			JSONArray entries = (JSONArray) obj.get(key);
			for (int i = 0; i < entries.length(); i++) {
				JSONObject tmp = entries.getJSONObject(i);
				// gtk, dtk, ltk
				JSONArray gtk_string = tmp.getJSONArray("gtk");
				JSONArray dtk_string = tmp.getJSONArray("dtk");
				JSONArray ltk_string = tmp.getJSONArray("ltk");
				byte[][] gtk = new byte[2][];
				byte[] dtk = jsonToBytes((JSONArray) dtk_string);
				List<byte[][]> ltk = new ArrayList<byte[][]>();
				for (int j = 0; j < gtk_string.length(); j++) {
					gtk[j] = jsonToBytes((JSONArray) gtk_string.get(j));
				}
				for (int j = 0; j < ltk_string.length(); j++) {
					byte[][] ltk_tmp = new byte[2][];
					JSONArray ltk_tmp_string = (JSONArray) ltk_string.get(j);
					for (int k = 0; k < ltk_tmp_string.length(); k++) {
						ltk_tmp[k] = jsonToBytes((JSONArray) ltk_tmp_string.get(k));
					}
					ltk.add(ltk_tmp);
				}
				
				// make TOKEN Dis
				TokenDIS newtoken = new TokenDIS(gtk,dtk,ltk);
				tokenlist.add(newtoken);
				
			}
			// add to hashmap
			token.put(key, tokenlist);
		}
		
		return token;
		
	}
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	
	private static Multimap<String, String> padLookup1(Multimap<String, String> lookup) {

		Multimap<String, String> output = ArrayListMultimap.create();
		for (String key : lookup.keySet()) {
			String paddedKey = Strings.padEnd(key, 32, '*');
			output.putAll(paddedKey, lookup.get(key));
		}
		return output;
	}

	private static Multimap<String, String> padLookup2(Multimap<String, String> lookup) {

		Multimap<String, String> output = ArrayListMultimap.create();
		
		for (String key : lookup.keySet()) {
			Collection<String> values = lookup.get(key);
	        for(String value : values){
	        	String paddedValue = Strings.padEnd(value, 32, '*');
	        	output.put(key, paddedValue);
	        }
		}
		return output;
	}
	
	public static void getDisj(String key, String pathName) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException, IOException, InterruptedException, ExecutionException {
		List<byte[]> listSKs = new ArrayList<byte[]>();
		
		byte[] masterKey = hexStringToByteArray(key);
		
		listSKs.add(CryptoPrimitives.generateHmac(masterKey, "1"));
		listSKs.add(CryptoPrimitives.generateHmac(masterKey, "2"));
		listSKs.add(CryptoPrimitives.generateHmac(masterKey, "3"));
		
		//String pathName = "test/";

		ArrayList<File> listOfFile = new ArrayList<File>();
		

		TextProc.listf(pathName, listOfFile);
		

		TextProc.TextProc(false, pathName);
		

		// we need SKs to make the multimap? ?? 
		IEX2Lev disj = IEX2Lev.setup(listSKs, padLookup1(TextExtractPar.lp1), padLookup2(TextExtractPar.lp2), bigBlock, smallBlock, 0);
		String filename = "stream.ser";
		try {
			FileOutputStream file = new FileOutputStream(filename);
			ObjectOutputStream out = new ObjectOutputStream(file); 
			
			out.writeObject(disj);
			out.close();
			
			file.close();
			System.out.println("Setup completed");
		}
		catch(IOException ex) 
        { 
            System.out.println("Should never get here"); 
        } 
  
		
	}
	
	
	// create a while loop that is constantly listening for requests. 
	
	public static void main(String[] args) throws Exception {
		IEX2Lev disj = null;
		
		
		System.out.println("Buffered Reader Begins Here");
		try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in))) {
			String input;
		    while ((input = br.readLine()) != null) {
		    	String[] command = input.split(" ", 2);
		    	if (command[0].equals("setup")) {
		    		String[] inputs = command[1].split(",", 2);
		    		getDisj(inputs[0],inputs[1]);
		    	}
		    	else if (command[0].equals("receive")) {
		    		try
		            {    
		                // Reading the object from a file 
		    			String filename = "stream.ser";
		                FileInputStream file = new FileInputStream(filename); 
		                ObjectInputStream in = new ObjectInputStream(file); 
		                  
		                // Method for deserialization of object 
		                disj = (IEX2Lev)in.readObject(); 
		                  
		                in.close(); 
		                file.close(); 
		                  
		                System.out.println("Received!");
		            } 
		              
		            catch(IOException ex) 
		            { 
		                System.out.println("Should never get here"); 
		            } 
		             
		    		
		    	}
		    	else if (command[0].equals("query")) {
		    		if (disj != null) {
		    			String jsonString = command[1];
			        	JSONObject obj = new JSONObject(jsonString);
			        	Map<String, List<TokenDIS>> tokens = getTokens(obj);
			        	query_BIEX(disj,tokens);	
		    		}
		    		else {
		    			System.out.println("disj is null");
		    		}
		        }
		    }
		    } catch (IOException ioe) {
		      // Not possible. No error message can make sense of this.
		      throw new Error("ERROR: Input exception");
		    }
		}		
}
