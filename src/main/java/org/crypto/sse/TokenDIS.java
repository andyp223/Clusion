/** * Copyright (C) 2016 Tarik Moataz
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

//***********************************************************************************************//

/////////////////////    Generation of the token of IEX-ZMF 
//***********************************************************************************************//	

package org.crypto.sse;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

public class TokenDIS implements Serializable {

	public byte[][] tokenMMGlobal;
	public byte[] tokenDIC;
	public List<byte[][]> tokenMMLocal = new ArrayList<byte[][]>();
//
//	public TokenDIS(List<String> subSearch, List<byte[]> listOfkeys) throws UnsupportedEncodingException {
//
//		
//		
//		this.tokenMMGlobal = RR2Lev.token(listOfkeys.get(0), subSearch.get(0));
//		this.tokenDIC = CryptoPrimitives.generateHmac(listOfkeys.get(1), 3 + subSearch.get(0));
//		
//		byte[] bytes = subSearch.get(0).getBytes();
//		
//		
//		System.out.println("TOKENDIS");
//		for (int i = 0; i  < bytes.length; i++) {
//			System.out.print(Byte.toUnsignedInt(bytes[i]) + ",");
//		}
//		System.out.println();
//
//		for (int i = 1; i < subSearch.size(); i++) {
//			tokenMMLocal.add(
//					RR2Lev.token(CryptoPrimitives.generateHmac(listOfkeys.get(0), subSearch.get(0)), subSearch.get(i)));
//		}
//
//	}
//	
	public TokenDIS(List<byte[]> subSearch, List<byte[]> listOfkeys) throws UnsupportedEncodingException {

		
	
		this.tokenMMGlobal = RR2Lev.token(listOfkeys.get(0), subSearch.get(0));
//		this.tokenDIC = CryptoPrimitives.generateHmac(listOfkeys.get(1), 3 + subSearch.get(0));
		
		byte[] keywordBytes = new byte[33];
		
		keywordBytes[0] = "3".getBytes()[0];
		for (int i = 1; i < 33; i++) {
			keywordBytes[i] = subSearch.get(0)[i-1];
		}
		this.tokenDIC = CryptoPrimitives.generateHmac(listOfkeys.get(1), keywordBytes);
		
		byte[] bytes = subSearch.get(0);
	

		for (int i = 1; i < subSearch.size(); i++) {
			tokenMMLocal.add(
					RR2Lev.token(CryptoPrimitives.generateHmac(listOfkeys.get(0), subSearch.get(0)), subSearch.get(i)));
		}

	}
	
	public TokenDIS(byte[][] tokenMMGlobal, byte[] tokenDIC, List<byte[][]> tokenMMLocal) {
		this.tokenMMGlobal = tokenMMGlobal;
		this.tokenDIC = tokenDIC;
		this.tokenMMLocal = tokenMMLocal;
	}

	public byte[][] getTokenMMGlobal() {
		return tokenMMGlobal;
	}

	public void setTokenMMGlobal(byte[][] tokenMMGlobal) {
		this.tokenMMGlobal = tokenMMGlobal;
	}

	public byte[] getTokenDIC() {
		return tokenDIC;
	}

	public void setTokenDIC(byte[] tokenDIC) {
		this.tokenDIC = tokenDIC;
	}

	public List<byte[][]> getTokenMMLocal() {
		return tokenMMLocal;
	}

	public void setTokenMMLocal(List<byte[][]> tokenMMLocal) {
		this.tokenMMLocal = tokenMMLocal;
	}
	
	public void printTokenDic() {
		for (int i = 0; i < this.tokenDIC.length; i++) {
			System.out.print(Byte.toUnsignedInt(this.tokenDIC[i]) + ",");
		}
	}
	
	public void printTokenMMGlobal() {

		System.out.println("\nGTK1:");
		for (int j = 0; j < this.tokenMMGlobal[0].length; j++) {
			System.out.print(Byte.toUnsignedInt(this.tokenMMGlobal[0][j]) + ",");
		}

		System.out.println("\nGTK2:");
		for (int j = 0; j < this.tokenMMGlobal[1].length; j++) {
			System.out.print(Byte.toUnsignedInt(this.tokenMMGlobal[1][j]) + ",");
		}
	}
	

	public void printTokenMMLocal() {
		for (int i = 0; i < this.tokenMMLocal.size(); i++) {
			byte[][] curr = this.tokenMMLocal.get(i);
			
			for (int j = 0; j < curr.length; j++) {
				for (int k = 0; k < curr[j].length; k++) {
					System.out.print(Byte.toUnsignedInt(curr[j][k]) + ",");		
				}
				System.out.print("\n");
			}
			System.out.print("\n\n");
		}
	}


}
