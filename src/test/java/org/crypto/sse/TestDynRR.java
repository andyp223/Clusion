package org.crypto.sse;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
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
import java.util.Random;
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
		String hmac_utk1 = Arrays.toString(CryptoPrimitives.generateHmac(utk1.getBytes("UTF-8"), "" + 1));
		Map<String,byte[]> utk = new HashMap<String,byte[]>();
		utk.put(hmac_utk1, utk2bytes);
		DynRR.update(dictionary, utk); 
	}
	
	private static void updateBatch(String input, ConcurrentMap<String, byte[]> dictionary) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		String[] utks = input.split(",");
		Map<String,byte[]> utk_dict = new HashMap<String,byte[]>();
		long start = System.nanoTime();
		for (String utk : utks) {
			String utk1 = utk.substring(0,utk.length()/3);
			String utk2 = utk.substring(utk.length()/3);
			byte[] utk2bytes = utk2.getBytes("UTF-8");
			String hmac_utk1 = Arrays.toString(CryptoPrimitives.generateHmac(utk1.getBytes("UTF-8"), "" + 1));
			utk_dict.put(hmac_utk1, utk2bytes);
		}
		long hmacTime = System.nanoTime();
		DynRR.update(dictionary, utk_dict); 
		long endTime = System.nanoTime();
		System.out.println("HMAC time (ns): " + (hmacTime-start));
		System.out.println("EDX put time (ns): " + (endTime-hmacTime));
	}
	
	//query
	private static String query(String utk, ConcurrentMap<String, byte[]> dictionary) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		long start = System.nanoTime();
		String token = Arrays.toString(CryptoPrimitives.generateHmac(utk.getBytes("UTF-8"), "" + 1));
		byte[] result = DynRR.query(token, dictionary);
		String output = new String(result,StandardCharsets.UTF_8);
//		DO NOT CHANGE. Output needs to be parsed as such
		System.out.println(output + "," + ((System.nanoTime()-start)));
		return output;
	}
	
    private static String getRandomHexString(int numchars){
        Random r = new Random();
        StringBuffer sb = new StringBuffer();
        while(sb.length() < numchars){
            sb.append(Integer.toHexString(r.nextInt()));
        }

        return sb.toString().substring(0, numchars);
    }
    
    // static set up. generates num_tokens of random tokens
	public static void setup2(int num_tokens, ConcurrentMap<String, byte[]> dictionary) throws UnsupportedEncodingException {
		int batch = 1000000;
		int count = 0;
		// only generates in batches of 1 million
		if (num_tokens > batch) {
			for (int i = 0; i < (num_tokens/batch); i ++) {
//				System.out.println("i: " + i);
				Map<String,byte[]> utk = new HashMap<String,byte[]>();
				for (int j = 0; j < batch; j++) {					
					String tk1 = getRandomHexString(64);
					String tk2 = getRandomHexString(128);
					utk.put(tk1, tk2.getBytes("UTF-8"));
					count += 1;
				}
				System.out.println("count: " + count);
				DynRR.update(dictionary,utk);
			}
			
		} else {
			Map<String,byte[]> utk = new HashMap<String,byte[]>();
			for (int i = 0; i < num_tokens; i ++) {
				String tk1 = getRandomHexString(64);
				String tk2 = getRandomHexString(128);
				utk.put(tk1, tk2.getBytes("UTF-8"));
			}
			DynRR.update(dictionary,utk);			
		}
	}
	public static void setup(String filename, ConcurrentMap<String, byte[]> dictionary) throws UnsupportedEncodingException, IOException {
		String csvfile = filename;
		String line = "";
		BufferedReader br;
		long startTime = System.nanoTime();
		Map<String,byte[]> utk = new HashMap<String,byte[]>();
		try {
			br = new BufferedReader(new FileReader(csvfile));
			int counter = 0;
			while ((line = br.readLine()) != null) {
				counter = counter + 1;
				int tmp = counter % 1000;
				if (tmp == 0) {
					try {
				        File f1 = new File("temp.txt");
				        if(!f1.exists()) {
				           f1.createNewFile();
				        }
						FileWriter writer = new FileWriter(f1.getName(),true);
						BufferedWriter bw = new BufferedWriter(writer);
						bw.write("Lines Read = " + counter + " \n");
						bw.close();
					} catch(IOException e) {
						System.out.println("SHOULD NEVER GET HERE");
					}
				}

				String[] contents = line.split(",");
				String utk1 = contents[0];
				String utk2 = contents[1];
				byte[] utk2bytes = utk2.getBytes("UTF-8");
				String hmac_utk1 = Arrays.toString(CryptoPrimitives.generateHmac(utk1.getBytes("UTF-8"), "" + 1));
				utk.put(hmac_utk1, utk2bytes);
			}
			DynRR.update(dictionary, utk); 
		} catch (FileNotFoundException e) {
			System.out.println("SHOULD NEVER GET HERE");
		}
		long endTime = System.nanoTime();
		long duration = (endTime-startTime)/1000000;
		try {
	        File f1 = new File("temp.txt");
	        if(!f1.exists()) {
	           f1.createNewFile();
	        }
			FileWriter writer = new FileWriter(f1.getName(),true);
			BufferedWriter bw = new BufferedWriter(writer);
			bw.write("Duration = " + duration + " \n");
			bw.close();
		} catch(IOException e) {
			System.out.println("SHOULD NEVER GET HERE");
		}
		
	}
	
	public static void main(String[] args) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException  { 
		DB db = DBMaker.fileDB("test.db").fileMmapEnable().fileMmapPreclearDisable()
			.allocateStartSize(1000 * 1024 * 1024).allocateIncrement(250 * 1024 * 1024).make();

//		DB db = DBMaker.fileDB("test.db").fileMmapEnable().fileMmapPreclearDisable()
//				.allocateStartSize(1000000).allocateIncrement(1000000).make();
		
		ConcurrentMap<String, byte[]> dictionary = (ConcurrentMap<String, byte[]>) db.hashMap("test").createOrOpen();		

		// build initial EMM 
		System.out.println("Buffered Reader Begins Here");
		try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in))) {
			String input;
			while ((input = br.readLine()) != null) {
		    		String[] command = input.split(" ", 2);
			    if (command[0].equals("setup")) {
			    	setup(command[1], dictionary);
			    }
			    else if (command[0].equals("setup2")) {
					long start = System.nanoTime();
			    	setup2(Integer.parseInt(command[1]), dictionary);
		            System.out.println("static setup time (ns): " + ((System.nanoTime()-start)));
			    }
			    else if (command[0].equals("update")) {
					long start = System.nanoTime();
			    	update(command[1], dictionary);
		            System.out.println("update time (ns): " + ((System.nanoTime()-start)));
		        }
			    else if (command[0].equals("updateBatch")) {
					long start = System.nanoTime();
	        		updateBatch(command[1], dictionary);
	        		long endTime = System.nanoTime() - start;
		            System.out.println("update batch time (ns): " + endTime);
			    }
		        else if (command[0].equals("query")) {
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
