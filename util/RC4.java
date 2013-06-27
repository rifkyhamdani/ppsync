package util;

import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author rifky
 */
public class RC4 {

    public static int ENCRYPT = 0, DECRYPT = 1;
    private Cipher cipher;
    private static String instance = "RC4";

    /**
     * constructor
     */
    public RC4(SecretKeySpec key, int mode) throws Exception {
        cipher = Cipher.getInstance(instance);
        if (mode == ENCRYPT) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
    }

    /**
     * generate RC4key
     */
    public static byte[] keyGen() {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance(instance);
            kgen.init(128);
            SecretKey skey = kgen.generateKey();
            byte[] raw = skey.getEncoded();
            return raw;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * convert raw byte from key generator to secret key
     */
    public static SecretKeySpec convertBytesToSecretKey(byte[] raw) {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, instance);
        return skeySpec;
    }
    
    /**
     * convert secret key spec to bytes
     */
    public static byte [] convertSecretKeyToBytes(SecretKeySpec key) {
        byte[] raw = key.getEncoded();
        return raw;
    }

    /**
     * get input stream
     */
    public CipherInputStream getBindingInputStream(InputStream is) {
        return new CipherInputStream(is, cipher);
    }

    /**
     * get output stream
     */
    public CipherOutputStream getBindingOutputStream(OutputStream os) {
        return new CipherOutputStream(os, cipher);
    }

    /**
     * get block size of chiper
     */
    public int getBlockSize() {
        return cipher.getBlockSize();
    }
}
