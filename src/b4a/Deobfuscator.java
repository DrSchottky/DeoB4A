package b4a;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;


public class Deobfuscator {
	
	/*EXAMPLE*/
	/*From Code*/
	private static byte[] enc_txt = new byte[]{(byte) 44, (byte) 62, (byte) 53, (byte) 89, (byte) 121, (byte) 41, (byte) 56, (byte) 18, (byte) 39, (byte) 39, (byte) 50, (byte) 69, (byte) 50, (byte) 37, (byte) 53, (byte) 5, (byte) 46, (byte) 121, (byte) 51, (byte) 1, (byte) 48, (byte) 60, (byte) 103, (byte) 19, (byte) 62, (byte) 44, (byte) 97, (byte) 84, (byte) 38, (byte) 47, (byte) 44, (byte) 89, (byte) 112, (byte) 36, (byte) 53, (byte) 18, (byte) 52, (byte) 44, (byte) 35, (byte) 9, (byte) 37, (byte) 99, (byte) 49, (byte) 7, (byte) 123, (byte) 112, (byte) 39, (byte) 7, (byte) 53};
	private static int enc_key = 4321;
	/*From Manifest*/
	private static String pkg = "com.evilsoft.lolsec";
	private static String ver_name = "6.6.6";
	private static int ver_code = 10;
	
	
	public static void main(String[] args) {
	String dec_txt="";
	System.out.println("Encrypted string: " + Arrays.toString(enc_txt));
	try {
		dec_txt = decrypt(enc_txt, enc_key, pkg, ver_name, ver_code);
		System.out.println("Decrypted string: " + dec_txt);
			
	} catch (UnsupportedEncodingException e) {
		e.printStackTrace();
	}


	}
	
	public static String decrypt(byte[] payload, int key, String package_name, String version_name, int version_code) throws UnsupportedEncodingException  {
        
		byte[][] _b = new byte[4][];
        try {
			_b[0] = package_name.getBytes("UTF8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
        _b[1] = version_name.getBytes("UTF8");
        if (_b[1].length == 0) {
            _b[1] = "jsdkfh".getBytes("UTF8");
        }
        _b[2] = new byte[]{(byte) version_code};
        
        int value = (key / 7) + 1234;
        _b[3] = new byte[]{(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value};
        for (int i = 0; i < 4; i++) {
            int j = 0;
            while (j < payload.length) {
                try {
                    payload[j] = (byte) (payload[j] ^ _b[i][j % _b[i].length]);
                    j++;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
    
        return new String(payload,"UTF8");
	}
	
	public static byte [] encrypt(String payload, int key, String package_name, String version_name, int version_code) throws UnsupportedEncodingException {
		return decrypt(payload.getBytes(), key, package_name, version_name, version_code).getBytes();
	}

}
