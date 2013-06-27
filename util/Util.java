//ousted:null
package util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 *
 * @author rifky
 */
public class Util {

    /**
     * encrypt plaintext to chipertext using RSA Algorithm
     * @param plain = data to be encrypted
     * @param pub = public key
     * @return
     */
    public static byte[] RSAEncrypt(byte[] plain, PublicKey pub) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            byte[] cipherData = cipher.doFinal(plain);
            return cipherData;
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * decrypt chipertext to plaintext using RSA Algorithm
     * @param chiper = data to bed decrypted
     * @param pri = private key
     * @return
     */
    public static byte[] RSADecrypt(byte[] chiper, PrivateKey pri) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, pri);
            byte[] cipherData = cipher.doFinal(chiper);
            return cipherData;
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * convert bytes to public key
     * @param raw
     * @return
     */
    public static PublicKey convertBytesToPublicKey(byte[] raw) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(raw));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * convert bytes to private key
     * @param raw
     * @return
     */
    public static PrivateKey convertBytesToPrivateKey(byte[] raw) {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(raw));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * convert bytes to hex
     * @param bytes
     * @return
     */
    public static String convertBytesToHex(byte[] bytes) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            int halfbyte = (bytes[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                if ((0 <= halfbyte) && (halfbyte <= 9)) {
                    buf.append((char) ('0' + halfbyte));
                } else {
                    buf.append((char) ('a' + (halfbyte - 10)));
                }
                halfbyte = bytes[i] & 0x0F;
            } while (two_halfs++ < 1);
        }
        return buf.toString();
    }

    /**
     * convert hex to string
     * @param hex
     * @return
     */
    public static String convertHexToString(String hex) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    /**
     * convert bytes to string
     * @param bytes
     * @return
     */
    public static String convertBytesToString(byte[] bytes) {
        try {
            return new String(bytes, "iso-8859-1");
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * convert string to bytes
     * @param s
     * @return
     */
    public static byte[] convertStringToBytes(String s) {
        try {
            return s.getBytes("iso-8859-1");
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * convert base64 to bytes
     * @param base64String
     * @return
     */
    public static byte[] convertBase64ToBytes(String base64String) {
        BASE64Decoder base64 = new BASE64Decoder();
        try {
            return base64.decodeBuffer(base64String);
        } catch (IOException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * convert bytes to base64
     * @param bytes
     * @return
     */
    public static String convertBytesToBase64(byte[] bytes) {
        BASE64Encoder base64 = new BASE64Encoder();
        return base64.encode(bytes);
    }

    /**
     * get SHA of a file
     * @param file
     * @return
     */
    public static byte[] getSHA(File file) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            MessageDigest md;
            md = MessageDigest.getInstance("SHA-1");
            byte[] sha1hash = new byte[20];
            byte[] buf = new byte[1024];
            int len;
            while ((len = fis.read(buf)) > 0) {
                md.update(buf, 0, len);
            }
            sha1hash = md.digest();
            fis.close();
            return sha1hash;
        } catch (Exception e) {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException ex) {
                    Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            return null;
        }
    }

    /**
     * Get MD5 of a String
     * @param text
     * @return
     */
    public static String getMD5(String text) {
        try {
            MessageDigest md;
            md = MessageDigest.getInstance("MD5");
            md.update(text.getBytes("iso-8859-1"));
            return convertBytesToBase64(md.digest());
//            return couconvertBytesToHex(md.digest());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * compare byte1 and byte2
     * @param b1
     * @param b2
     * @return return true if true and false if false
     */
//    public static boolean compareBytes(byte[] b1, byte[] b2) {
//        if (b1.length != b2.length) {
//            return false;
//        }
//        for (int i = 0; i < b1.length; i++) {
//            if (b1[i] != b2[i]) {
//                return false;
//            }
//        }
//        return true;
//    }
    
    /**
     * compare byte1 and byte2
     * @param b1
     * @param b2
     * @return return true if true and false if false
     */
    public static boolean compareBytes(byte[] b1, byte[] b2) {
        if (Util.convertBytesToBase64(b1).equals(Util.convertBytesToBase64(b2))) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * get UTF length of a string
     * @param text = text to be get its length
     * @return length of a string if error return 0;
     */
    public static int getUTFLength(String text) {
        try {
            return text.getBytes("UTF-8").length + 2;
        } catch (Exception e) {
            return 0;
        }
    }
}
