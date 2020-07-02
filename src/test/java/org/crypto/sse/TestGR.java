package org.crypto.sse;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.NoSuchPaddingException;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.TreeMultimap;

// Multimap setup 

// update 

// query 

public class TestGR {
	// updating the searchable encrypted db
	public static DynRH2Lev update(String filename, byte[] sk, DynRH2Lev twolev) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException, InvalidKeySpecException {
		System.out.println("Currently in update phase");
		ArrayList<File> listOfFile = new ArrayList<File>();
		TextProc.listf(filename, listOfFile);		
		TextProc.TextProc(false, filename);
		TreeMultimap<String, byte[]> tokenUp = DynRH2Lev.tokenUpdate(sk, TextExtractPar.lp1);
		DynRH2Lev.update(twolev.getDictionaryUpdates(), tokenUp);
		
		return twolev;	
	}
	
	
	// querying the searchable encrypted db 
	public static List<String> query(String keyword, byte[] sk, DynRH2Lev twolev) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		System.out.println("Currently in query phase");
		byte[][] token = DynRH2Lev.genToken(sk, keyword);
		
		List<String> hello = DynRH2Lev.resolve(CryptoPrimitives.generateCmac(sk, 3 + new String()),
				twolev.query(token, twolev.getDictionary(), twolev.getArray(), twolev.getDictionaryUpdates()));
		
		return hello;
	}
	
	// create a while loop that is constantly listening for requests. 
	
	public static void main(String[] args) throws Exception {
		String pass = "hello world"; // NOTE: Should this be our key ? 
		byte[] sk = RR2Lev.keyGen(256, pass, "salt/salt", 100000);
		//System.out.println(new BouncyCastleProvider().getVersion());
		try {
	        File f1 = new File("temp.txt");
	        if(!f1.exists()) {
	           f1.createNewFile();
	        }
			FileWriter writer = new FileWriter(f1.getName(),true);
			BufferedWriter bw = new BufferedWriter(writer);
			bw.write("hello \n");
			bw.close();
		} catch(IOException e) {
			System.out.println("SHOULD NEVER GET HERE");
		}
		
		System.out.println("Generating searchable map"); 
		System.out.println("Working Directory = " +
	              System.getProperty("user.dir"));
		long startTime = System.nanoTime();
		String pathName = "test"; // relative path to the files 

		ArrayList<File> listOfFile = new ArrayList<File>();
		TextProc.listf(pathName, listOfFile);

		TextProc.TextProc(false, pathName);
		
		int bigBlock = 1000;
		int smallBlock = 100;
		int dataSize = 10000;

		// // Construction of the global multi-map
		System.out.println("\nBeginning of Encrypted Multi-map creation \n");

		DynRH2Lev twolev = DynRH2Lev.constructEMMParGMM(sk, TextExtractPar.lp1, bigBlock, smallBlock, dataSize);

		// Empty the previous multimap

		TextExtractPar.lp1 = ArrayListMultimap.create();
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
		System.out.println("Duration = " + duration);
		System.out.println("Buffered Reader Begins Here");
		try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in))) {
			String input;
		    while ((input = br.readLine()) != null) {
		    		String[] command = input.split(" ", 2);
		        if (command[0].equals("update")) {
		        		twolev = update(command[1],sk,twolev);
		        }
		        else if (command[0].equals("query")) { // NOTE: we want to return the token note the file name
		        		System.out.println(query(command[1],sk,twolev));
		        } else {
		            System.out.println("ERROR: Invalid Input");
		            return;
		        }
		    }
		    } catch (IOException ioe) {
		      // Not possible. No error message can make sense of this.
		      throw new Error("ERROR: Input exception");
		    }
		}		
}
