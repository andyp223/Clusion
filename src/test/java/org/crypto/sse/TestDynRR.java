package org.crypto.sse;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.nio.charset.StandardCharsets;
import javax.crypto.NoSuchPaddingException;

import org.mapdb.DB;
import org.mapdb.DBMaker;

public class TestDynRR {
	// update
	private static void update(String input, ConcurrentMap<String, byte[]> dictionary) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		String utk1 = input.substring(0,input.length()/3);
		String utk2 = input.substring(input.length()/3);
		byte[] utk2bytes = utk2.getBytes("UTF-8");
		//System.out.println(utk1);
		//System.out.println(Arrays.toString(utk2bytes));
		String hmac_utk1 = Arrays.toString(CryptoPrimitives.generateHmac(utk1.getBytes("UTF-8"), "" + 1));
		//System.out.println(hmac_utk1);
		Map<String,byte[]> utk = new HashMap<String,byte[]>();
		utk.put(hmac_utk1, utk2bytes);
		DynRR.update(dictionary, utk); 
	}
	
	//query
	private static String query(String utk, ConcurrentMap<String, byte[]> dictionary) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		//System.out.println(utk);
		String token = Arrays.toString(CryptoPrimitives.generateHmac(utk.getBytes("UTF-8"), "" + 1));
		byte[] result = DynRR.query(token, dictionary);
		String output = new String(result,StandardCharsets.UTF_8);
		System.out.println(output);
		return output;
	}

	
	public static void main(String[] args) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException  { 
		DB db = DBMaker.fileDB("test.db").fileMmapEnable().fileMmapPreclearDisable()
			.allocateStartSize(124 * 1024 * 1024).allocateIncrement(5 * 1024 * 1024).make();
		ConcurrentMap<String, byte[]> dictionary = (ConcurrentMap<String, byte[]>) db.hashMap("test").createOrOpen();		

		//System.out.println("Buffered Reader Begins Here");
		try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in))) {
			String input;
		    while ((input = br.readLine()) != null) {
		    		String[] command = input.split(" ", 2);
		        if (command[0].equals("update")) {
		        		update(command[1], dictionary);
		        }
		        else if (command[0].equals("query")) { // NOTE: we want to return the token note the file name
		        		query(command[1], dictionary);
		        } else {
		            System.out.println("ERROR: Invalid Input");
		        }
		    }
		    } catch (IOException ioe) {
		      // Not possible. No error message can make sense of this.
		      throw new Error("ERROR: Input exception");
		    }
			db.close();
		}
		
		
	}
