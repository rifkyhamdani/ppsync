package tracker;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.PrivateKey;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import protocol.Communication;
import protocol.Message;
import protocol.MetaFilesPeer;
import protocol.SyncCmd;
import util.RC4;
import util.Util;

/**
 *
 * @author rifky
 */
public class ServerTracker extends Thread {

    Socket socket; /* socket to peer */
    InputStream is; /* inputstream from peer */
    OutputStream os; /* outputstream to peer */
    String address; /* ipaddress of peer that connected to tracker */
    String addressPort; /* ipaddress and port */
    SecretKeySpec RC4Key; /* RC4Key in format SecretKeySpec */
    String RC4KeyBase64; /* RC4Key in format Base64 */
    RC4 decrypt, encrypt; /* decrypt and encrypt using RC4 */
    String username = "";
    boolean haslogin;
    private String usernamePeer = "psync";
    //private String passwordPeer = "5e8ce2358e65e8624ba20e3aab33d99e";
    private String passwordPeer = "XoziNY5l6GJLog46qzPZng==";
    private String prikeystring = "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAmmWmlc4vWZE0gkmLw8uxtZ5pckHG\n"
            + "lpOu2esYxOAEQ6zpYmxZIXAmoBgojXOMvjCb1GkNNT5eDUQmGzgp11fvYwIDAQABAkAXpyr2GDg4\n"
            + "yH3617mJrVL0N+h/kIQT3VwUFmgdARSmKUI5W5ZomfU2IF1kZQf21w3JXSeX5SH8eWQyVsnTMBzB\n"
            + "AiEA0TJ8gM4GzYdschFA0m6Kot5WVIQVLFvwo80MSvl3jk0CIQC88I28EbgkQylG/Q3mReHTauGJ\n"
            + "cWW6up+T9PRH3jwsbwIhAI35Am/z4sAHgTykouZtKN9Bnzs6bJgvSVARL5+OUGodAiEAvJUJku7I\n"
            + "sgELARzxM6cKmN+0T2AM3s0JHD/BVr5dpycCIADKvnyQl4uFKduyxW2VVBuvTy9Gv8S1qn+6vPKj\n"
            + "5REp";
    private PrivateKey prikey = Util.convertBytesToPrivateKey(Util.convertBase64ToBytes(prikeystring));
    MetaFilesPeer metaFilesPeer; /* MetaFilePeer */
    SyncCmd syncCmd; /* Synchronization Command */
    int portServerPeer;
    int iduser; /* for database */
    String usernamepeerdb;

    /**
     * Constructor
     */
    public ServerTracker(Socket socket) throws Exception {
        this.socket = socket;
        is = this.socket.getInputStream();
        os = this.socket.getOutputStream();
        address = socket.getInetAddress().toString();
        if (address.equals("/127.0.0.1")) {
            address = InetAddress.getLocalHost().getHostAddress();
        }
        System.out.println(address);
        syncCmd = new SyncCmd();
        System.out.println("Incomming connection from " + address + " on port " + String.valueOf(socket.getPort()));
    }

    @Override
    public void run() {
        try {
            /* main program here */
            Communication.readHandshake(is); /* ready to accept handshake */
            System.out.println("Get handshake from " + address + "on port " + String.valueOf(socket.getPort()));
            Communication.sendHandshake(os); /* send handshake */

            while (!haslogin) {
                try {
                    haslogin = readAuth();
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }
                if (haslogin) {
                    System.out.println("Authentication Successful");
                }
                respAuth();
            }
            receivePort();
            synchronized (GUITracker.onlinePeer) {
                GUITracker.onlinePeer.add(addressPort);
            }

            if (!GUITracker.lastUpdate.containsKey(addressPort)) {
                GUITracker.lastUpdate.put(addressPort, Long.MIN_VALUE);
            }

            while (haslogin && GUITracker.isStart) {
                DataInputStream dis = new DataInputStream(is);
                try {
                    int len = dis.readInt();
                    int msgid = dis.readByte();
                    if (msgid == Message.MSG_LOGOUT) {
                        haslogin = false;
                    } else if (msgid == Message.MSG_SEND_KEY) { /* read RC4Key */
                        receiveKey();
                    } else if (msgid == Message.MSG_SEND_META) { /* read meta file from peer */
                        readMetaFile(); /* send meta file from peer */
                        makeSyncCommand(); /* synchronization here */
                        sendSyncCommand(); /* send synchronization command */
                    } else if (msgid == Message.MSG_CHANGE_KEY) { /* change RC4Key */
                        updateBindingRC4Key();
                    } else if (msgid == Message.MSG_IHAVE) { /* send i have message to tracker */
                        receiveIHave(dis);
                    } else if (msgid == Message.MSG_CHANGE_LASTUPDATE) { /* change lastupdate */
                        changeLastUpdate(addressPort);
                    } else if (msgid == Message.MSG_PAUSE) {
                        GUITracker.onlinePeer.remove(addressPort);
                    } else if (msgid == Message.MSG_PLAY) {
                        GUITracker.onlinePeer.add(addressPort);
                    } else {
                        sendError();
                    }
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                    return;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error: " + e.getMessage() + " from " + addressPort);
        } catch (ErrorMessageException ex) {
            Logger.getLogger(ServerTracker.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                synchronized (GUITracker.onlinePeer) {
                    GUITracker.onlinePeer.remove(addressPort);
                }
                this.socket.close();
            } catch (Exception e) {
            }
            System.out.println("Connection from " + addressPort + " is closed");
        }
    }

    /**
     * read authentication
     */
    private boolean readAuth() throws Exception {
        DataInputStream dis = new DataInputStream(is);
        int len = dis.readInt();
        int msgId = dis.readByte();
        if (msgId != Message.MSG_AUTH) {
            throw new Exception("Kode autentikasi salah");
        }
        username = dis.readUTF();
        byte[] password = new byte[len - 1 - Util.getUTFLength(username)];
        dis.read(password);
        String plainpassword = new String(Util.RSADecrypt(password, prikey), "iso-8859-1");
        System.out.println("username: " + username + " password: " + plainpassword);
        String passwordMD5 = Util.getMD5(Util.convertBytesToString(Util.RSADecrypt(password, prikey)));
        System.out.println(passwordMD5);
        System.out.println(username);
        return checkLogin(username, passwordMD5);
    }

    /**
     * response Authentication to peer
     */
    private void respAuth() throws Exception {
        DataOutputStream dos = new DataOutputStream(os);
        dos.writeInt(1);
        dos.writeByte(Message.MSG_RESP_AUTH);
        if (haslogin) {
            dos.writeByte(Message.SUCCESS_AUTH);
        } else {
            dos.writeByte(Message.FAILED_AUTH);
        }
    }

    /**
     * check username and hash of password is correct
     */
    private boolean checkLogin(String username, String passwordMD5) {
        try {
            Statement stmt = GUITracker.conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * from account where username='" + username + "' and password='" + passwordMD5 + "'");
            if (rs.next()) {
                //iduser = rs.getInt("Id");
                return true;
            } else {
                return false;
            }            
            
//            if ((username.equals(usernamePeer)) && (passwordMD5.equals(passwordPeer))) {
//                return true;
//            } else {
//                return false;
//            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * send message error to peer
     */
    private void sendError() throws IOException {
        System.out.println("Error Message");
        DataOutputStream dos = new DataOutputStream(os);
        dos.writeInt(1);
        dos.writeByte(Message.MSG_ERROR_STATUS);
    }

    /**
     * read meta file from peer
     */
    private void readMetaFile() throws Exception, ErrorMessageException {
        System.out.println("Read Meta File");
        DataInputStream dis = new DataInputStream(is);
        metaFilesPeer = new MetaFilesPeer();
        while (true) {
            /* read parent */
            String parent = dis.readUTF();
            if (parent.equals("//")) {
                break;
            }
            String name = dis.readUTF();
            boolean isfile = dis.readBoolean();
            byte[] sha = null;
            if (isfile) {
                String shaBase64 = dis.readUTF();
                sha = Util.convertBase64ToBytes(shaBase64);
            }
            long timeadded = dis.readLong();
            metaFilesPeer.addMetaFile(parent, name, isfile, sha, timeadded);
        }
    }

    /**
     * send synchronization command to peer
     */
    private void sendSyncCommand() throws IOException {
        System.out.print(addressPort);
        System.out.println("Send Synchronizatin Command");
        DataOutputStream dos = new DataOutputStream(os);
        for (int i = 0; i < syncCmd.list.size(); i++) {
            System.out.print("CODE: ");
            System.out.println(syncCmd.list.get(i).code);
            System.out.print("PARENT1: ");
            System.out.println(syncCmd.list.get(i).parent1);
            System.out.print("PARENT2: ");
            System.out.println(syncCmd.list.get(i).parent2);
            System.out.print("NAME1: ");
            System.out.println(syncCmd.list.get(i).name1);
            System.out.print("NAME2: ");
            System.out.println(syncCmd.list.get(i).name2);
            System.out.print("ADDRESSPORT: ");
            System.out.println(syncCmd.list.get(i).addressPort);
        }

        for (int i = 0; i < syncCmd.list.size(); i++) {
            dos.writeByte(syncCmd.list.get(i).code);
            dos.writeUTF(syncCmd.list.get(i).parent1);
            dos.writeUTF(syncCmd.list.get(i).parent2);
            dos.writeUTF(syncCmd.list.get(i).name1);
            dos.writeUTF(syncCmd.list.get(i).name2);
            dos.writeUTF(syncCmd.list.get(i).addressPort);
        }
        dos.writeByte(Message.MSG_NEW_KEY);
        synchronized (GUITracker.onlinePeer) {
            dos.writeUTF(Util.convertBytesToBase64(GUITracker.RC4KeyByte));
        }
    }

    /**
     * make synchronization command
     */
    private void makeSyncCommand() {
        synchronized (GUITracker.metaFilesTracker) {
            System.out.print(addressPort);
            System.out.println("Make Synchronization Command");
            SyncCmd tempSyncCmd = new SyncCmd();

            int j, k;
            String parent1, parent2, name1, name2, address2;
            long timeadded;
            byte[] sha;

            System.out.println("PEER:");
            for (int i = 0; i < metaFilesPeer.list.size(); i++) {
                System.out.println(metaFilesPeer.list.get(i).parent + metaFilesPeer.list.get(i).name);
            }

            System.out.println("TRACKER");
            for (int i = 0; i < GUITracker.metaFilesTracker.list.size(); i++) {
                System.out.println(GUITracker.metaFilesTracker.list.get(i).parent + GUITracker.metaFilesTracker.list.get(i).name);
            }

            for (int i = 0; i < metaFilesPeer.list.size(); i++) {
                if (metaFilesPeer.list.get(i).isFile) { /* file */
                    j = GUITracker.metaFilesTracker.getIndexMetaFileWithPath(metaFilesPeer.list.get(i).parent, metaFilesPeer.list.get(i).name);
                    k = GUITracker.metaFilesTracker.getIndexFileWithSHA(metaFilesPeer.list.get(i).sha);
                    if (j != -1) { /* same path */
                        if (k != -1) { /* same path, same sha */
                            /* do nothing */

                        } else { /* same path, different sha */
                            if (GUITracker.lastUpdate.get(addressPort) > GUITracker.metaFilesTracker.list.get(j).timeAdded) { /* lastupdate > timeaddedtracker */
                                /* delete */
                                System.out.println("UPDATE1 DELETE");
                                parent1 = metaFilesPeer.list.get(i).parent;
                                name1 = metaFilesPeer.list.get(i).name;
                                sha = metaFilesPeer.list.get(i).sha;
                                timeadded = metaFilesPeer.list.get(i).timeAdded;
                                System.out.println("UPDATE1B ADD");
                                GUITracker.metaFilesTracker.delMetaFile(j);
                                /* add */
                                GUITracker.metaFilesTracker.addMetaFile(parent1, name1, true, sha, timeadded, addressPort);

                            } else if (GUITracker.metaFilesTracker.list.get(j).timeAdded > GUITracker.lastUpdate.get(addressPort) && GUITracker.lastUpdate.get(addressPort) > metaFilesPeer.list.get(i).timeAdded) { /* timeaddedtracker > lastupdate > timeaddedpeer */
                                /* sync delete */
                                System.out.println("UPDATE2 DELETE");
                                name1 = metaFilesPeer.list.get(i).name;
                                parent1 = metaFilesPeer.list.get(i).parent;
                                tempSyncCmd.addCommand(SyncCmd.DELETE, parent1, "", name1, "", "");

                                /* sync download */
//                                parent2 = GUITracker.metaFilesTracker.list.get(j).parent;
//                                ArrayList<String> owners = GUITracker.metaFilesTracker.list.get(j).owners;
//                                ArrayList<String> tempOwner = new ArrayList<String>();
//
//                                for (int l = 0; l < owners.size(); l++) {
//                                    if (isOnline(owners.get(l))) {
//                                        tempOwner.add(owners.get(l));
//                                    }
//                                }
//
//                                int Min = 0, Max = tempOwner.size() - 1;
//                                int res = Min + (int) (Math.random() * ((Max - Min) + 1));
//                                address2 = tempOwner.get(res);
//
//                                tempSyncCmd.addCommand(SyncCmd.DOWNLOAD, parent2, "", name1, "", address2);
                            } else { /* timeaddedtracker > lastupdate < timeaddedpeer */
                                /* add */
                                System.out.println("UPDATE3 RENAME DOWNLOAD");
                                parent1 = metaFilesPeer.list.get(i).parent;
                                name1 = metaFilesPeer.list.get(i).name;
                                name2 = addressPort + "_" + name1;
                                sha = metaFilesPeer.list.get(i).sha;
                                timeadded = metaFilesPeer.list.get(i).timeAdded;
                                GUITracker.metaFilesTracker.addMetaFile(parent1, name2, true, sha, timeadded, addressPort);

                                /* sync rename */
                                tempSyncCmd.addCommand(SyncCmd.RENAME, parent1, "", name1, name2, "");

                                /* sync download */
                                ArrayList<String> owners = GUITracker.metaFilesTracker.list.get(j).owners;
                                ArrayList<String> tempOwner = new ArrayList<String>();

                                for (int l = 0; l < owners.size(); l++) {
                                    if (isOnline(owners.get(l))) {
                                        tempOwner.add(owners.get(l));
                                    }
                                }

                                int Min = 0, Max = tempOwner.size() - 1;
                                int res = Min + (int) (Math.random() * ((Max - Min) + 1));
                                address2 = tempOwner.get(res);

                                parent2 = GUITracker.metaFilesTracker.list.get(j).parent;
                                tempSyncCmd.addCommand(SyncCmd.DOWNLOAD, parent2, "", name1, "", address2);
                            }
                        }
                    } else { /* no same path */
                        if (GUITracker.lastUpdate.get(addressPort) <= metaFilesPeer.list.get(i).timeAdded) { /* lastupdate <= timeadded */
                            /* add */
                            System.out.println("UPDATE4 ADD");
                            parent1 = metaFilesPeer.list.get(i).parent;
                            name1 = metaFilesPeer.list.get(i).name;
                            sha = metaFilesPeer.list.get(i).sha;
                            timeadded = metaFilesPeer.list.get(i).timeAdded;
                            GUITracker.metaFilesTracker.addMetaFile(parent1, name1, true, sha, timeadded, addressPort);
                        } else { /* lastupdate > timeadded */
                            /* sync delete */
                            System.out.println("UPDATE5 DELETE");
                            parent1 = metaFilesPeer.list.get(i).parent;
                            name1 = metaFilesPeer.list.get(i).name;
                            tempSyncCmd.addCommand(SyncCmd.DELETE, parent1, "", name1, "", "");
                        }
                    }
                } else { /* folder */
                    j = GUITracker.metaFilesTracker.getIndexMetaFileWithPath(metaFilesPeer.list.get(i).parent, metaFilesPeer.list.get(i).name);
                    if (j != -1) { /* same path */
                        /* do nothing */

                    } else { /* no same path */
                        if (GUITracker.lastUpdate.get(addressPort) <= metaFilesPeer.list.get(i).timeAdded) { /* lastupdate <= timeadded */
                            /* add */
                            System.out.println("UPDATE6 ADD");
                            parent1 = metaFilesPeer.list.get(i).parent;
                            name1 = metaFilesPeer.list.get(i).name;
                            timeadded = metaFilesPeer.list.get(i).timeAdded;
                            GUITracker.metaFilesTracker.addMetaFile(parent1, name1, false, null, timeadded, addressPort);
                        } else { /* lastupdate > timeadded */
                            /* sync delete */
                            System.out.println("UPDATE7 DELETE");
                            parent1 = metaFilesPeer.list.get(i).parent;
                            name1 = metaFilesPeer.list.get(i).name;
                            tempSyncCmd.addCommand(SyncCmd.DELETE, parent1, "", name1, "", "");
                        }
                    }
                }

            }

            for (int i = 0; i < GUITracker.metaFilesTracker.list.size(); i++) {
                if (GUITracker.metaFilesTracker.list.get(i).isFile) { /* file */
                    j = metaFilesPeer.getIndexMetaFileWithPath(GUITracker.metaFilesTracker.list.get(i).parent, GUITracker.metaFilesTracker.list.get(i).name);
                    if (j != -1) { /* same path */
                        /* already handled above*/

                    } else { /* no same path */
                        if (GUITracker.lastUpdate.get(addressPort) >= GUITracker.metaFilesTracker.list.get(i).timeAdded) { /* lastupdate >= timeadded */
                            /* delete */
                            System.out.println("UPDATE8 DELETE");
                            GUITracker.metaFilesTracker.delMetaFile(i);
                        } else { /* lastupdate < timeadded */
                            k = metaFilesPeer.getIndexMetaFileWithSHA(GUITracker.metaFilesTracker.list.get(i).sha);
                            if (k != -1) { /* same sha */
                                /* sync copy */
                                System.out.println("UPDATE9 COPY");
//                                parent1 = metaFilesPeer.list.get(k).parent;
                                parent2 = GUITracker.metaFilesTracker.list.get(i).parent;
//                                name1 = metaFilesPeer.list.get(k).name;
                                name2 = GUITracker.metaFilesTracker.list.get(i).name;
//                                tempSyncCmd.addCommand(SyncCmd.COPY, parent1, parent2, name1, name2, "");
                                
                                ArrayList<String> owners = GUITracker.metaFilesTracker.list.get(i).owners;
                                ArrayList<String> tempOwner = new ArrayList<String>();

                                for (int l = 0; l < owners.size(); l++) {
                                    if (isOnline(owners.get(l))) {
                                        tempOwner.add(owners.get(l));
                                    }
                                }

                                int Min = 0, Max = tempOwner.size() - 1;
                                int res = Min + (int) (Math.random() * ((Max - Min) + 1));
                                address2 = tempOwner.get(res);

                                tempSyncCmd.addCommand(SyncCmd.DOWNLOAD, parent2, "", name2, "", address2);
                                
                            } else { /* no same sha */
                                /* sync download */
                                System.out.println("UPDATE10 DOWNLOAD");
                                name1 = GUITracker.metaFilesTracker.list.get(i).name;
                                parent1 = GUITracker.metaFilesTracker.list.get(i).parent;
                                ArrayList<String> owners = GUITracker.metaFilesTracker.list.get(i).owners;
                                ArrayList<String> tempOwner = new ArrayList<String>();

                                for (int l = 0; l < owners.size(); l++) {
                                    if (isOnline(owners.get(l))) {
                                        tempOwner.add(owners.get(l));
                                    }
                                }

                                int Min = 0, Max = tempOwner.size() - 1;
                                int res = Min + (int) (Math.random() * ((Max - Min) + 1));
                                address2 = tempOwner.get(res);

                                tempSyncCmd.addCommand(SyncCmd.DOWNLOAD, parent1, "", name1, "", address2);
                            }
                        }
                    }
                } else { /* folder */
                    j = metaFilesPeer.getIndexMetaFileWithPath(GUITracker.metaFilesTracker.list.get(i).parent, GUITracker.metaFilesTracker.list.get(i).name);
                    if (j != -1) { /* same path */
                        /* do nothing */

                    } else { /* no same path */
                        if (GUITracker.lastUpdate.get(addressPort) <= GUITracker.metaFilesTracker.list.get(i).timeAdded) { /* lastupdate <= timeaddtracker */
                            /* sync mkdir */
                            System.out.println("UPDATE11 MKDIR");
                            parent1 = GUITracker.metaFilesTracker.list.get(i).parent;
                            name1 = GUITracker.metaFilesTracker.list.get(i).name;
                            tempSyncCmd.addCommand(SyncCmd.MKDIR, parent1, "", name1, "", "");
                        } else { /* lastupdate > timeaddedpeer */
                            /* delete */
                            System.out.println("UPDATE12 DELETE");
                            GUITracker.metaFilesTracker.delMetaFile(i);
                        }
                    }
                }
            }
            syncCmd = tempSyncCmd;
        }
    }

    /**
     * action to be execute if receive key from peer
     */
    private void receiveKey() throws Exception {
        System.out.println("Receive Key");
        DataInputStream dis = new DataInputStream(is);
        String keyBase64 = dis.readUTF();
        byte[] key = Util.convertBase64ToBytes(keyBase64);
        byte[] rc4key = Util.RSADecrypt(key, prikey);
        synchronized (GUITracker.onlinePeer) {
            GUITracker.RC4KeyByte = rc4key;
        }
        RC4Key = RC4.convertBytesToSecretKey(rc4key);
        encrypt = new RC4(RC4Key, RC4.ENCRYPT);
        decrypt = new RC4(RC4Key, RC4.DECRYPT);
        CipherInputStream cis = decrypt.getBindingInputStream(socket.getInputStream());
        CipherOutputStream cos = encrypt.getBindingOutputStream(socket.getOutputStream());
        is = cis;
        os = cos;
        System.out.println("Get symmetric key from: " + addressPort);
    }

    /**
     * check if a peer is online, true if online, false if offline
     */
    private boolean isOnline(String addressport) {
        synchronized (GUITracker.onlinePeer) {
            for (int i = 0; i < GUITracker.onlinePeer.size(); i++) {
                if (GUITracker.onlinePeer.get(i).equals(addressport)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * update binding RC4 key
     */
    private void updateBindingRC4Key() throws Exception {
        System.out.println("Update Binding RC4Key");
        synchronized (GUITracker.onlinePeer) {
            RC4Key = RC4.convertBytesToSecretKey(GUITracker.RC4KeyByte);
        }
        encrypt = new RC4(RC4Key, RC4.ENCRYPT);
        decrypt = new RC4(RC4Key, RC4.DECRYPT);
        CipherInputStream cis = decrypt.getBindingInputStream(socket.getInputStream());
        CipherOutputStream cos = encrypt.getBindingOutputStream(socket.getOutputStream());
        is = cis;
        os = cos;
        System.out.print("RC4KEEEEY");
        System.out.println(Util.convertBytesToBase64(GUITracker.RC4KeyByte));
    }

    /**
     * receive i have message
     */
    private void receiveIHave(DataInputStream dis) throws IOException {
        String parent = dis.readUTF();
        String name = dis.readUTF();
        int index = GUITracker.metaFilesTracker.getIndexMetaFileWithPath(parent, name);
        GUITracker.metaFilesTracker.list.get(index).owners.add(addressPort);
    }

    /**
     * receive portServerPeer
     */
    private void receivePort() throws IOException {
        System.out.print(addressPort);
        System.out.println("Receive Port");
        DataInputStream dis = new DataInputStream(is);
        int msgId = dis.readByte();
        if (msgId == Message.MSG_SEND_PORT) {
            portServerPeer = Integer.valueOf(dis.readUTF());
            System.out.println(portServerPeer);
            addressPort = address + ":" + portServerPeer;
        }
    }

    private void changeLastUpdate(String addressport) {
        GUITracker.lastUpdate.put(addressport, System.currentTimeMillis());
    }

    class ErrorMessageException extends Throwable {
    }
}
