package protocol;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import util.Util;

/**
 *
 * @author rifky
 */
public class Communication {

    //public static int BUF_SIZE = 1024;
    public static int BUF_SIZE = 8192;

    /**
     * send handshake
     */
    public static void sendHandshake(OutputStream os) throws Exception {
        DataOutputStream dos = new DataOutputStream(os);
        int msgLength = Util.getUTFLength(Message.Identifier) + 1;
        dos.writeInt(msgLength); /* 4 byte length prefix */
        dos.writeByte(Message.MSG_HANDSHAKE); /* 1 byte message id */
        dos.writeUTF(Message.Identifier); /* payload */
    }

    /**
     * read handshake
     */
    public static void readHandshake(InputStream is) throws Exception {
        DataInputStream dis = new DataInputStream(is);
        int msgLength = dis.readInt(); /* don't be used because already know what to be read and its length */
        int msgId = dis.readByte();
        if (msgId != Message.MSG_HANDSHAKE) {
            throw new Exception("Handshake Message ID is wrong");
        }
        String identifier = dis.readUTF();
        if (!identifier.equals(Message.Identifier)) {
            throw new Exception("Protocol String Identifier is wrong");
        }
    }

    /**
     * Send File
     */
    public static void sendFile(OutputStream os, File file, String pathSend) throws Exception {
        FileInputStream fis = new FileInputStream(file);
        DataOutputStream dos = new DataOutputStream(os);
        dos.writeInt(fis.available() + 1 + Util.getUTFLength(pathSend) + 8); /* message length */
        dos.writeByte(Message.MSG_SEND_FILE); /* message id */
        dos.writeUTF(pathSend); /* path */
        dos.writeLong(file.lastModified()); /* last modified */
        byte[] buf = new byte[BUF_SIZE];
        while (fis.available() > 0) {
            int len = fis.read(buf);
            os.write(buf, 0, len);
        }
        fis.close();
    }

    /**
     * read file, prerequisite: file length, message id, & path are already read
     */
    public static void readFile(long fileLength, InputStream is, String path) throws Exception {
        DataInputStream dis = new DataInputStream(is);
        new File(path).getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(path);
        long dateModified = dis.readLong();
        byte[] buf = new byte[BUF_SIZE];
        long byteread = 0;
        while (byteread < fileLength) {
            if (fileLength - byteread < BUF_SIZE) {
                buf = new byte[(int) (fileLength - byteread)];
            }
            int len = is.read(buf);
            byteread += len;
            fos.write(buf, 0, len);
        }
        fos.close();
        new File(path).setLastModified(dateModified);
    }
}
