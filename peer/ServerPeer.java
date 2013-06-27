package peer;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import protocol.Communication;
import static protocol.Communication.BUF_SIZE;
import protocol.Message;
import util.*;

/**
 *
 * @author rifky
 */
public class ServerPeer extends Thread {

    Socket socketToPeer;
    InputStream isFromPeer;
    OutputStream osToPeer;
    String address;
    RC4 decrypt;
    RC4 encrypt;

    /**
     * Constructor
     */
    public ServerPeer(Socket socket) throws Exception {
        this.socketToPeer = socket;
        isFromPeer = this.socketToPeer.getInputStream();
        osToPeer = this.socketToPeer.getOutputStream();
        address = socket.getInetAddress().toString() + ":" + String.valueOf(socket.getPort());
        System.out.println("Incoming connection from " + address);
    }

    @Override
    public void run() {
        try {
            Communication.readHandshake(isFromPeer);
            System.out.println("Get handshake from" + address);
            Communication.sendHandshake(osToPeer);
            bindingStreamToRC4();

            while (true) {
                DataInputStream dis = new DataInputStream(isFromPeer);
                int len = dis.readInt();
                int msgid = dis.readByte();
                if (msgid == Message.MSG_REQ_FILE) {
                    System.out.println("Get request from other peer");
                    String path = dis.readUTF();
                    sendFile(osToPeer, GUIPeer.pathRepo + path);
                } else {
                    respRC4Cek();
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error: " + e.getMessage() + " from " + address);
        } finally {
            try {
                this.socketToPeer.close();
            } catch (Exception e) {
            }
        }
        System.out.println("Close connection from : " + address);
    }

    /**
     * send file to other peer
     */
    private void sendFile(OutputStream os, String path) throws FileNotFoundException, IOException {
        System.out.println("Send File to other peer");
        File file = new File(path);
        FileInputStream fis = new FileInputStream(file);
        DataOutputStream dos = new DataOutputStream(os);
        dos.writeInt(fis.available() + 1 + Util.getUTFLength(path) + 8); /* length */
        dos.writeByte(Message.MSG_SEND_FILE); /* message id */
        dos.writeUTF(path); /* path */
        dos.writeLong(file.lastModified()); /* last modified */
        byte[] buf = new byte[BUF_SIZE];
        while (fis.available() > 0) {
            int len = fis.read(buf);
            os.write(buf, 0, len);
        }
        fis.close();
    }

    /**
     * make I/O stream to be decrypted
     */
    private void bindingStreamToRC4() throws Exception {
        encrypt = new RC4(RC4.convertBytesToSecretKey(GUIPeer.RC4KeyByte), RC4.ENCRYPT);
        decrypt = new RC4(RC4.convertBytesToSecretKey(GUIPeer.RC4KeyByte), RC4.DECRYPT);
        CipherInputStream cis = decrypt.getBindingInputStream(socketToPeer.getInputStream());
        CipherOutputStream cos = encrypt.getBindingOutputStream(socketToPeer.getOutputStream());
        isFromPeer = cis;
        osToPeer = cos;
    }
    
    /**
     * send response to RC4Cek
     */
    private void respRC4Cek() throws Exception {
        DataInputStream dis = new DataInputStream(isFromPeer);
        DataOutputStream dos = new DataOutputStream(osToPeer);
        byte rc4cek2 = dis.readByte();
        dos.writeByte(Message.MSG_RC4CEK);
        
        bindingStreamToRC4();
    }
}
