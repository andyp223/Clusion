package org.crypto.sse;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import java.lang.Object;
import java.nio.charset.StandardCharsets;

import javax.crypto.NoSuchPaddingException;

public class TestBIEX {
	
	
	static int bigBlock = 1000;
	static int smallBlock = 100;

	public static void main(String[] args) throws Exception {


		List<byte[]> listSKs = new ArrayList<byte[]>();
		
		byte[] masterKey = hexStringToByteArray("b6ca37ab8d488e5157348b168d29e2ccc6aeda960a9a7cbba60bdd0df9ec90b7");
		
		listSKs.add(CryptoPrimitives.generateHmac(masterKey, "1"));
		listSKs.add(CryptoPrimitives.generateHmac(masterKey, "2"));
		listSKs.add(CryptoPrimitives.generateHmac(masterKey, "3"));
		
	
		// for (int i = 0; i < listSKs.size(); i++) {
		// 	System.out.println("key " + i + ": ");
		// 	for (int j = 0; j < listSKs.get(i).length; j++) {
		// 		System.out.print(Byte.toUnsignedInt(listSKs.get(i)[j]) + ",");
		// 	}
		// 	System.out.println("\n");
		// }
	
		
		String pathName = "test/";

		ArrayList<File> listOfFile = new ArrayList<File>();
		

		TextProc.listf(pathName, listOfFile);
		

		TextProc.TextProc(false, pathName);


		IEX2Lev disj = IEX2Lev.setup(listSKs, TextExtractPar.lp1, TextExtractPar.lp2, bigBlock, smallBlock, 0);

	
		
		// this is an example of how to perform boolean queries

		// number of disjunctions
		int numDisjunctions = 2;

		// Storing the CNF form
		byte[][][] query = new byte[numDisjunctions][][];
			
		
		query[0] = formatQuery("aa,bb");
		query[1] = formatQuery("cc,dd");
		
		
		Map<String, List<TokenDIS>> token =  token_BIEX(listSKs, query);
		query_BIEX(disj, token);
		
	}
	
	public static byte[][] formatQuery(String query) {
		

		String[] temp = query.split(",");

		byte[][] result = new byte[temp.length][32];
				
		for (int i = 0; i < temp.length; i++) {
			byte[] b = hexStringToByteArray(temp[i]);
			
			byte[] bytes = new byte[32];
			
			if (b.length < 32) {
				for (int j = 0; j < b.length; j++) {
					bytes[j] = b[j];
				}
				for (int j = b.length; j < 32; j++) {
					bytes[j] = 0;
				}
			}
			result[i] = bytes;
		}
		
		return result;
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
	
	
	public static Map<String, List<TokenDIS>> token_BIEX(List<byte[]> listSK, byte[][][] query) throws UnsupportedEncodingException {
		
		Map<String, List<TokenDIS>> token = new HashMap<String, List<TokenDIS>>();
		

		for (int i = 1; i < query.length; i++) {
			for (int k = 0; k < query[0].length; k++) {
				List<byte[]> searchTMP = new ArrayList<byte[]>();
				searchTMP.add(query[0][k]);
				
				for (int r = 0; r < query[i].length; r++) {
					searchTMP.add(query[i][r]);
				}
	
				List<TokenDIS> tokenTMP = IEX2Lev.tokenBytes(listSK, searchTMP);
				
				for (int j = 0; j < tokenTMP.size(); j++) {
					tokenTMP.get(j).printTokenMMGlobal();
					
					System.out.println("\nDict: ");
					tokenTMP.get(j).printTokenDic();
					System.out.println("\nLocal: ");
					
					tokenTMP.get(j).printTokenMMLocal();					
				}
				token.put(i+" "+k, tokenTMP);
			}
		}
		
		// Generate the IEX token
		List<byte[]> searchBol = new ArrayList<byte[]>();
		for (int i = 0; i < query[0].length; i++) {
			searchBol.add(query[0][i]);
		}
		List<TokenDIS> tokenGeneral = IEX2Lev.tokenBytes(listSK, searchBol);
		
		token.put(query.length+" "+query[0].length, tokenGeneral);
		
		System.out.println("general:");
		
		for (int i = 0; i < tokenGeneral.size(); i++) {
			
			System.out.println("\nGlobal: ");
			tokenGeneral.get(i).printTokenMMGlobal();
			
			System.out.println("\nDict: ");
			tokenGeneral.get(i).printTokenDic();
			System.out.println("\nLocal: ");
			
			tokenGeneral.get(i).printTokenMMLocal();
		}
		
		return token;
	}
	
	
	
	
	
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

		System.out.println("Final result " + tmpBol);


	}
	
	

}
