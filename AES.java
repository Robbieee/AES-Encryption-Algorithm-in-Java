import java.io.*;
import java.util.Arrays;
import java.util.Random;

//Written By Robert Freethy
//AES Encryption algorithm, will encrypt 1 16byte block with IV=0

public class AES {
	
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();	
	final protected static String[] RC = new String[]{"01","02","04","08","10","20","40","80","1B","36"};
	private static final char sbox[] = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
			0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72,
			0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04,
			0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c,
			0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20,
			0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33,
			0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
			0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e,
			0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde,
			0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4,
			0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba,
			0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5,
			0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69,
			0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
			0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
 
	
	
	
	// *************************************************//
	//               MAIN FUNCTION
	// *************************************************//	
	public static void main(String [] args){
		String plainText = new String("RobbieFreethy250");
		String key = generateRandomKey(16);
		encrypt (plainText,key);
	}
	
	
	
	// *************************************************//
	//               ENCRYPTION FUNCTIONS
	// *************************************************//	
	
	public static void encrypt(String plainText,String key){
		byte[] bytes;
		
		
		try {
			bytes = plainText.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			System.out.println(e);
			return;
		}
		
		encryptBlock(bytes, key, plainText);
	
	}
	
	
	public static void encryptBlock (byte [] block, String key ,String plainText){
		byte[][] state = stateInit(block);
		byte[][] words = keyExpansion(key);
		
		//System.out.println("-------- Initial State --------");
		//printState(state);
		
		//System.out.println("-------- Round 0 --------");
		//Before the first round, we add round key
		state = addRoundKey(state, Arrays.copyOfRange(words,0,4));
		
		//Rounds 1-9 are all the same
		for(int i = 1; i<10;i++) {
			//System.out.println("-------- Round "+ i +"--------");
			state = subBytes(state);
			//printState(state);
			state = shiftRows(state);
			//printState(state);
			state = mixColumns(state);
			//printState(state);
			state = addRoundKey(state, Arrays.copyOfRange(words,(i*4),((i+1)*4)));	
		}
		//Round 10 we dont mix Columns
		//System.out.println("-------- Round 10 --------");
		state = subBytes(state);
		state = shiftRows(state);
		state = addRoundKey(state, Arrays.copyOfRange(words,40,44));	
		
		//Lets turn our state into the cypher text
		String cypherText = new String();
		for (int i = 0; i < 4; i++){
			for (int j = 0; j < 4; j++){
				cypherText += bytesToHex(state[i][j]);
			}
		}
		
		
		//The Encryption algorithm has complete for this 16-byte block
		//lets print some details
		System.out.println("Plain Text: " + plainText);
		System.out.println("Plain Text (HEX): " + bytesToHex(block));
		System.out.println("Key: " + key);
		System.out.println("Cypher Text: " + cypherText);
	}
	
	
	public static void printState (byte [][] state){
		System.out.println("");
		for (int i = 0; i < 4; i++)
				System.out.println(bytesToHex( state[0][i]) + " " + bytesToHex( state[1][i]) + " " + bytesToHex( state[2][i]) + " " + bytesToHex( state[3][i]));
	}
	
	//Turn our hex plain text into a state array
	public static byte[][] stateInit(byte[] bytes){
		byte state[][] = new byte [4][4];
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				state[i][j] = (byte) bytes[4*i + j];
		return state;
	}
	
	//row 0 shifts by 0, row 1 shifts by 1 ...
	private static byte[][] shiftRows (byte[][] state) {
		byte newState[][] = new byte [4][4];
		for (int i = 0; i < 4; i++){
			for (int j = 0; j < 4; j++){
				newState[i][j] = state [(i+j)%4][j];
			}
		}
		return newState;
	}
	
	//This function does what the text book says it should :) 
	private static byte[][] mixColumns (byte[][] state) {
		byte newState[][] = new byte [4][4];
		
		byte times2 = (byte) 0x02;
		byte times3 = (byte) 0x03;
		
		int temp[] = new int [4];
		for (int j = 0; j < 4; j++){
			temp[0] = byteMultiply(times2,state[j][0]) ^ byteMultiply(times3,state[j][1]) ^ state[j][2] ^ state [j][3];
			temp[1] = state[j][0] ^ byteMultiply(times2,state[j][1]) ^ byteMultiply(times3,state[j][2]) ^ state [j][3];
			temp[2] = state[j][0] ^ state [j][1] ^ byteMultiply(times2,state[j][2]) ^ byteMultiply(times3,state[j][3]);
			temp[3] = byteMultiply(times3,state[j][0]) ^ state[j][1] ^ state [j][2] ^ byteMultiply(times2,state[j][3]);
			for (int i = 0; i < 4; i++){
				newState[j][i] = (byte) (temp[i]);
			}
		}

		return newState;
	}
	//Sub bytes from the cooresponding sbox array
	private static byte[][] subBytes (byte[][] state) {		
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				state[i][j] = (byte) sbox[state[i][j] & 0xFF];
		return state;
	}
	//16byte state array XOR compared with 16bytes of this round's 4 key words 
	private static byte[][] addRoundKey (byte [][] state, byte [][] roundKey) {
		byte[][] newState = new byte [4][4];
		for (int i = 0; i < 4; i++){
			for (int j = 0; j < 4; j++){
				newState [i][j] = (byte) (state [i][j] ^ roundKey[i][j]);
				
			}
		}
		return newState;
	}
	
	
	
	
	
	// *************************************************//
	//               KEY FUNCTIONS
	// *************************************************//
	private static String generateRandomKey(int length){
		char[] hexChars = new char[length * 2];
		Random rand = new Random(); 
		
		for ( int j = 0; j < hexChars.length; j++ ) {
			hexChars[j] = hexArray[rand.nextInt((15 - 0) + 1)];
		}
		
		return new String(hexChars);
	}
	
	//4byte random key is used to create 44 words 
	//Each word consists of 4 bytes, 8 hex letters
	private static byte [][] keyExpansion(String key){
		//44 words, 4 bytes each
		byte [][] words = new byte [44][4];
		//key is 16 bytes long, 32 hex letters
		byte [] keyBytes = new byte[key.length()/2];
		
	    for (int i = 0; i < key.length(); i += 2) {
	    	keyBytes[i / 2] = (byte) ((Character.digit(key.charAt(i), 16) << 4)
	                             + Character.digit(key.charAt(i+1), 16));
	    }
	    
		//The key will become first 4 words
	    //16byte key = 4bytes/word * 4words
		for (int i = 0;i<4;i++){
			words[i][0] = keyBytes[4*i];
			words[i][1] = keyBytes[4*i+1];
			words[i][2] = keyBytes[4*i+2];
			words[i][3] = keyBytes[4*i+3];
			//System.out.println("Word"+ (i+1) + ": " + bytesToHex(words[i][0])+ bytesToHex(words[i][1])+ bytesToHex(words[i][2])+ bytesToHex(words[i][3]));
		}
		
		//Lets loop through for our other 40 words
		//word[x] depends on word[x-1] and word[x-4] -> XOR comparison, as always
		//Every fourth word we'll run things through the blender a bit
		byte [] temp = new byte[4];
		for (int i = 4;i<44;i++){
			temp = words[i-1];
			
			//Do this once per round
			if (i % 4 == 0){
				//Substitute the rotated word
				temp = SubWord (RotWord (temp));
				//XOR bitwise comparison with leftmost Byte and the current RC(round counter) value
				temp [0] = (byte) (temp[0] ^ (byte) ((Character.digit(RC[i/4 - 1].charAt(0), 16) << 4)
                        + Character.digit(RC[i/4 - 1].charAt(1), 16)));
			}
			
			for (int j = 0;j<4;j++){
				words[i][j] = (byte) (words[i-4][j] ^ temp[j]);	
			}
			//System.out.println("Word"+ (i+1) + ": " + bytesToHex(words[i][0])+ bytesToHex(words[i][1])+ bytesToHex(words[i][2])+ bytesToHex(words[i][3]));
		}
		return words;		
	}
	
	//Called by keyExpansion  - will move byte0 to the end of the word
	private static byte [] RotWord (byte [] word){
		byte [] bytes = new byte [4];
		bytes [0] = word[1];
		bytes [1] = word[2];
		bytes [2] = word[3];
		bytes [3] = word[0];
		return (bytes);
	}
	
	//Called by keyExpansion - flip these bytes with the sbox
	private static byte [] SubWord (byte [] word){
		byte [] temp = new byte[4];
	
	    //And then do the byte subs to the sbox
	    for (int i = 0;i<4;i++){
	    	temp[i] += (byte) sbox[word[i] & 0xFF];
	    }
		return temp;
		
	}
	
	
	
	
	
	// *************************************************//
	//               HELPER FUNCTIONS
	// *************************************************//
	
	
	public static byte byteMultiply(byte b1, byte b2) {
		byte result = 0, t;
		
		while (b1 != 0) {
			if ((b1 & 1) != 0){
				result = (byte) (result ^ b2);
			}
			
			t = (byte) (b2 & 0x80);
			b2 = (byte) (b2 << 1);
			
			if (t != 0){
				b2 = (byte) (b2 ^ 0x1b);
			}
			
			b1 = (byte) ((b1 & 0xff) >> 1);
			
		}

		return result;
	}
	
	
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	
	public static String bytesToHex(byte b) {
	    char[] hexChars = new char[2];
        
	    int v = b & 0xFF;
        hexChars[0] = hexArray[v >>> 4];
        hexChars[1] = hexArray[v & 0x0F];
        
	    return new String(hexChars);
	}
}
