package peer;

import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Scanner;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import protocol.Communication;
import protocol.Message;
import protocol.MetaFilesPeer;
import protocol.SyncCmd;
import protocol.SyncCmd.Command;
import util.RC4;
import util.Util;

/**
 *
 * @author rifky
 */
public class ClientPeer extends Thread {

    public InputStream isFromTracker;
    public OutputStream osToTracker;
    public InputStream isFromPeer;
    public OutputStream osToPeer;
    public static long lastUpdate;
    Socket socketToTracker;
    Socket socketToPeer;
    public String username;
    public String password;
    public String host;
    public int portClient;
    public String pathRepo;
    public byte[] RC4KeyByte;
    private String pubKeyString = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJplppXOL1mRNIJJi8PLsbWeaXJBxpaTrtnrGMTgBEOs\n"
            + "6WJsWSFwJqAYKI1zjL4wm9RpDTU+Xg1EJhs4KddX72MCAwEAAQ==";
    private PublicKey pubKey = Util.convertBytesToPublicKey(Util.convertBase64ToBytes(pubKeyString));
    public MetaFilesPeer metaFilesPeer;
    public MetaFilesPeer tempMetaFilesPeer;
    SyncCmd syncCmd;
    public static long refreshPeriod = 3000;

    /**
     * constructor
     */
    public ClientPeer(String ipTracker, int portNum, String path, String username, String password) throws Exception {
        metaFilesPeer = new MetaFilesPeer();
        readMetaFilePeerFromFile();
        socketToTracker = new Socket(ipTracker, portNum);
        System.out.println("Client PSync Start...");
        isFromTracker = socketToTracker.getInputStream();
        osToTracker = socketToTracker.getOutputStream();
        this.username = username;
        this.password = password;
        this.host = ipTracker;
        this.portClient = portNum;
        this.pathRepo = path;

        Communication.sendHandshake(osToTracker);
        Communication.readHandshake(isFromTracker);
        sendAuth();
        receiveRespAuth();
        GUIPeer.login = true;//cek this variable
        sendPort();
    }

    @Override
    public void run() {
        String error = null;
        try {
            generateNewRC4Key();
            sendRC4Key();
            bindingRC4ToStream();
            while (GUIPeer.login) { //always true
                makeTempMetaFiles(); /* make temporary metafile */
                updateMetaFile(); /* update metafile client */
                writeMetaFilePeerToFile(); /* write new metafile */
                sendMetaFiles(); /* sent metafile to tracker */
                receiveSyncCommand(); /* read synchronization command from tracker */
                boolean success = doSync(); /* synchronize file with synchronization command  */
                if (success && syncCmd.list.isEmpty()) {
                    sendRequestChangeLastUpdate();
                }
                checkRC4(); /* check if RC4Key is changed */

                long start = System.currentTimeMillis();
                while (System.currentTimeMillis() < start + refreshPeriod) {
                    Thread.sleep(10);
                }

                if (GUIPeer.pause) {
//                    pause(); /* send pause to server */
                    while (GUIPeer.pause) {
                        Thread.sleep(10);
                    }
                }
                play(); /* send play to server */

            }
            logOut();
        } catch (Exception e) {
            error = e.toString();
            e.printStackTrace();
            try {
                isFromTracker.close();
                osToTracker.close();
                socketToTracker.close();
            } catch (IOException ex) {
            }
        } finally {
            try {
                isFromTracker.close();
                osToTracker.close();
                socketToTracker.close();
            } catch (IOException ex) {
            }
        }
    }

    /**
     * send authentication to tracker
     */
    private void sendAuth() throws Exception {
        DataOutputStream dos = new DataOutputStream(osToTracker);
        byte[] encryptedpassword = Util.RSAEncrypt(password.getBytes("iso-8859-1"), pubKey);
        dos.writeInt(1 + Util.getUTFLength(username) + encryptedpassword.length);
        dos.writeByte(Message.MSG_AUTH);
        dos.writeUTF(username);
        dos.write(encryptedpassword);
    }

    /**
     * read response authentication sent by tracker
     */
    private void receiveRespAuth() throws Exception {
        DataInputStream dis = new DataInputStream(isFromTracker);
        int msgLength = dis.readInt();
        int msgId = dis.readByte();
        int statuscode = dis.readByte();
        if (statuscode == Message.FAILED_AUTH) { /* Authentication Failed */
            socketToTracker.close();
            throw new Exception("Username or Password is wrong");
        } else if (statuscode == Message.SUCCESS_AUTH) { /* Authentication Success */
            /* do nothing, continue operation */
            System.out.println("Authentication Success");
        }
    }

    /**
     * read meta file peer from file
     */
    private void readMetaFilePeerFromFile() throws FileNotFoundException, IOException {
        File f = new File(pathRepo + "/metafile.txt");
        if (f.exists()) { /* metafile exist */
            FileInputStream fis = new FileInputStream(pathRepo + "/metafile.txt");
            Scanner s = new Scanner(fis);
            String[] metaFile;
            String name, path;
            byte[] sha = null;
            boolean isfile;
            long timeadded;
            while (s.hasNext()) {
                metaFile = s.nextLine().split("##");
                path = metaFile[0];
                name = metaFile[1];
                isfile = (metaFile[2].equals("1"));
                if (isfile) {
                    sha = Util.convertBase64ToBytes(metaFile[3]);
                }
                timeadded = Long.parseLong(metaFile[4]);
                metaFilesPeer.addMetaFile(path, name, isfile, sha, timeadded);
            }
            fis.close();
        } else { /* metafile don't exist */
            /* do nothing, continue operation */

        }
    }

    /**
     * generate new RC4Key
     */
    public void generateNewRC4Key() {
        RC4KeyByte = RC4.keyGen();
        GUIPeer.RC4KeyByte = RC4KeyByte;
    }

    /**
     * send RC4Key to Tracker
     */
    public void sendRC4Key() throws IOException {
        DataOutputStream dos = new DataOutputStream(osToTracker);
        byte[] RC4KeyByteEncrypted = Util.RSAEncrypt(RC4KeyByte, pubKey);
        String RC4KeyByteEncryptedBase64 = Util.convertBytesToBase64(RC4KeyByteEncrypted);
        dos.writeInt(1 + Util.getUTFLength(RC4KeyByteEncryptedBase64));
        dos.writeByte(Message.MSG_SEND_KEY);
        dos.writeUTF(RC4KeyByteEncryptedBase64);
        System.out.println("Send RC4 Key to Tracker");
    }

    /**
     * binding RC4 to Stream
     */
    public void bindingRC4ToStream() throws Exception {
        RC4 encrypt = new RC4(RC4.convertBytesToSecretKey(RC4KeyByte), RC4.ENCRYPT);
        RC4 decrypt = new RC4(RC4.convertBytesToSecretKey(RC4KeyByte), RC4.DECRYPT);
        CipherOutputStream cos = encrypt.getBindingOutputStream(socketToTracker.getOutputStream());
        CipherInputStream cis = decrypt.getBindingInputStream(socketToTracker.getInputStream());
        isFromTracker = cis;
        osToTracker = cos;
        System.out.println("Binding RC4 to Stream");
    }

    /**
     * make meta files
     */
    private void makeTempMetaFiles() throws Exception {
        System.out.println("Make Temporary Meta File");
        tempMetaFilesPeer = new MetaFilesPeer();
        makeTempMetaFiles("/", new File(pathRepo));
    }

    /**
     * make meta files
     */
    private void makeTempMetaFiles(String pathUp, File f) throws Exception {
        File[] l = f.listFiles();
        if (l != null) {
            long timeadded = System.currentTimeMillis();
            for (int i = 0; i < l.length; i++) {
                byte[] sha = null;
                boolean isfile;
                if (l[i].isDirectory()) {
                    isfile = false;
                } else {
                    isfile = true;
                    sha = Util.getSHA(l[i]);
                }
                if (!l[i].getName().equals(".DS_Store") && !l[i].getName().equals("metafile.txt") && !l[i].getName().equals("temp") && !l[i].getName().equals("log.txt")) {
                    tempMetaFilesPeer.addMetaFile(pathUp.replace("//", "/"), l[i].getName(), isfile, sha, timeadded);
                }
                if (l[i].isDirectory()) {
                    makeTempMetaFiles(pathUp + "/" + l[i].getName() + "/", l[i]);
                }
            }
        }
    }

    /**
     * Update meta files from temp meta file, true if changed false if not
     */
    private void updateMetaFile() {
        System.out.println("Update Meta File");
        int j, k;

        System.out.println("Metafile:");
        for (int i = 0; i < metaFilesPeer.list.size(); i++) {
            System.out.println(metaFilesPeer.list.get(i).parent + metaFilesPeer.list.get(i).name);
        }

        System.out.println("TempMetafile:");
        for (int i = 0; i < tempMetaFilesPeer.list.size(); i++) {
            System.out.println(tempMetaFilesPeer.list.get(i).parent + tempMetaFilesPeer.list.get(i).name);
        }

        /* Every meta file in temp meta file*/
        for (int i = 0; i < tempMetaFilesPeer.list.size(); i++) {
            if (tempMetaFilesPeer.list.get(i).isFile) { /* a file */
                j = metaFilesPeer.getIndexMetaFileWithSHA(tempMetaFilesPeer.list.get(i).sha);
                if (j == -1) { /* not found file with same SHA */
                    k = metaFilesPeer.getIndexMetaFileWithPath(tempMetaFilesPeer.list.get(i).parent, tempMetaFilesPeer.list.get(i).name);
                    if (k == -1) { /* different path */
                        /* add metafile */
                        metaFilesPeer.addMetaFile(tempMetaFilesPeer.list.get(i));
                        System.out.println("UPDATE1");
                    } else { /* same path */
                        /* delete metafile */
                        metaFilesPeer.delMetaFile(k);
                        System.out.println("UPDATE2");
                        /* add new metafile */
                        metaFilesPeer.addMetaFile(tempMetaFilesPeer.list.get(i));
                        System.out.println("UPDATE3");
                    }
                } else { /* found file with same SHA */
                    if (metaFilesPeer.list.get(j).parent.equals(tempMetaFilesPeer.list.get(i).parent) && metaFilesPeer.list.get(j).name.equals(tempMetaFilesPeer.list.get(i).name)) { /* same path */
                        /* do nothing */

                    } else { /* different path */
                        k = metaFilesPeer.getIndexMetaFileWithPath(tempMetaFilesPeer.list.get(i).parent, tempMetaFilesPeer.list.get(i).name);
                        if (k != -1) { /* exist file with same path and sha */
                            /* do nothing */

                        } else { /* don't exist file with same path */
                            /* add meta file */
                            metaFilesPeer.addMetaFile(tempMetaFilesPeer.list.get(i));
                            System.out.println("UPDATE4");
                        }
                    }
                }
            } else { /* a folder */
                j = metaFilesPeer.getIndexMetaFileWithPath(tempMetaFilesPeer.list.get(i).parent, tempMetaFilesPeer.list.get(i).name);
                if (j != -1) { /* found folder with same path */
                    /* do nothing */

                } else { /* not found folder with same path */
                    /* add */
                    metaFilesPeer.addMetaFile(tempMetaFilesPeer.list.get(i));
                    System.out.println("UPDATE5");
                }
            }
        }

        System.out.println("Metafile:");
        for (int i = 0; i < metaFilesPeer.list.size(); i++) {
            System.out.println(metaFilesPeer.list.get(i).parent + metaFilesPeer.list.get(i).name);
        }

        System.out.println("TempMetafile:");
        for (int i = 0; i < tempMetaFilesPeer.list.size(); i++) {
            System.out.println(tempMetaFilesPeer.list.get(i).parent + tempMetaFilesPeer.list.get(i).name);
        }

        /* Every meta file in meta files */
        for (int i = 0; i < metaFilesPeer.list.size(); i++) {
            if (metaFilesPeer.list.get(i).isFile) { /* a file */
                j = tempMetaFilesPeer.getIndexMetaFileWithSHA(metaFilesPeer.list.get(i).sha);
                if (j == -1) { /* not found file with same SHA */
                    /* delete */
                    metaFilesPeer.delMetaFile(i);
                    System.out.println("UPDATE6");
                } else { /* found file with same SHA */
                    if (metaFilesPeer.list.get(i).parent.equals(tempMetaFilesPeer.list.get(j).parent) && metaFilesPeer.list.get(i).name.equals(tempMetaFilesPeer.list.get(j).name)) { /* same path */
                        /* do nothing */

                    } else { /* different path */
                        k = tempMetaFilesPeer.getIndexMetaFileWithPath(metaFilesPeer.list.get(i).parent, metaFilesPeer.list.get(i).name);
                        System.out.println(metaFilesPeer.list.get(i).parent + metaFilesPeer.list.get(i).name);
                        if (k == -1) { /* no same path */
                            /* delete */
                            metaFilesPeer.delMetaFile(i);
                            System.out.println("UPDATE7");
                        } else { /* same path */
                            /* do nothing */

                        }
                    }
                }
            } else { /* folder */
                j = tempMetaFilesPeer.getIndexMetaFileWithPath(metaFilesPeer.list.get(i).parent, metaFilesPeer.list.get(i).name);
                if (j == -1) { /* not found folder in temp meta files*/
                    /* delete */
                    metaFilesPeer.delMetaFile(i);
                    System.out.println("UPDATE8");
                } else { /* found folder in temp meta files*/
                    /* do nothing */

                }
            }
        }
    }

    /**
     * make connection to other peer
     */
    public void connectToPeer(String ipPeer, int portNum) throws Exception {
        System.out.println("Connect to Peer");
        System.out.println(portNum);
        socketToPeer = new Socket(ipPeer.replace("/", ""), portNum);
        System.out.println("Connect to " + ipPeer + " on port number: " + portNum);
        isFromPeer = socketToPeer.getInputStream();
        osToPeer = socketToPeer.getOutputStream();
        Communication.sendHandshake(osToPeer);
        Communication.readHandshake(isFromPeer);

        RC4 encrypt = new RC4(RC4.convertBytesToSecretKey(GUIPeer.RC4KeyByte), RC4.ENCRYPT);
        RC4 decrypt = new RC4(RC4.convertBytesToSecretKey(GUIPeer.RC4KeyByte), RC4.DECRYPT);
        CipherOutputStream cos = encrypt.getBindingOutputStream(socketToPeer.getOutputStream());
        CipherInputStream cis = decrypt.getBindingInputStream(socketToPeer.getInputStream());
        isFromPeer = cis;
        osToPeer = cos;
        System.out.println("Binding RC4 to Stream");



//        byte rc4cek = 1;
//
//        while (Message.MSG_RC4CEK != rc4cek) {
//            RC4 encrypt = new RC4(RC4.convertBytesToSecretKey(GUIPeer.RC4KeyByte), RC4.ENCRYPT);
//            RC4 decrypt = new RC4(RC4.convertBytesToSecretKey(GUIPeer.RC4KeyByte), RC4.DECRYPT);
//            CipherOutputStream cos = encrypt.getBindingOutputStream(socketToPeer.getOutputStream());
//            CipherInputStream cis = decrypt.getBindingInputStream(socketToPeer.getInputStream());
//            isFromPeer = cis;
//            osToPeer = cos;
//            System.out.println("Binding RC4 to Stream");
//            rc4cek = RC4Cek();
//        }

        System.out.println("Connected to " + ipPeer + " on port " + portNum);
    }

    /**
     * disconnect from other peer
     */
    private void disconnectToPeer() throws IOException {
        System.out.println("Disconnect from Other Peer");
        try {
            isFromPeer.close();
            osToPeer.close();
            socketToPeer.close();
        } catch (Exception e) {
        }

    }

    /**
     * delete directory and its content
     */
    private void delTreeDir(File dir) throws Exception {
        if (dir.exists()) {
            File[] f = dir.listFiles();
            for (int i = 0; i < f.length; i++) {
                if (f[i].isDirectory()) {
                    delTreeDir(f[i]);
                }
                f[i].delete();
            }
            dir.delete();
        }
    }

    /**
     * send Meta file to tracker
     */
    private void sendMetaFiles() throws IOException {
        System.out.println("Send Meta Files");
        DataOutputStream dos = new DataOutputStream(osToTracker);
        dos.writeInt(1);
        dos.writeByte(Message.MSG_SEND_META);
        for (int i = 0; i < metaFilesPeer.list.size(); i++) {
            dos.writeUTF(metaFilesPeer.list.get(i).parent);
            dos.writeUTF(metaFilesPeer.list.get(i).name);
            dos.writeBoolean(metaFilesPeer.list.get(i).isFile);
            if (metaFilesPeer.list.get(i).isFile) {
                dos.writeUTF(Util.convertBytesToBase64(metaFilesPeer.list.get(i).sha));
            }
            dos.writeLong(metaFilesPeer.list.get(i).timeAdded);
        }
        dos.writeUTF("//");
    }

    /**
     * request file from other peer
     */
    private void reqFile(String path) throws Exception {
        System.out.println("Request File to Other Peer");
        DataOutputStream dos = new DataOutputStream(osToPeer);
        String filereq = path;
        dos.writeInt(1 + Util.getUTFLength(filereq));
        dos.writeByte(Message.MSG_REQ_FILE);
        dos.writeUTF(filereq);
    }

    /**
     * send logout message to tracker
     */
    private void logOut() throws Exception {
        DataOutputStream dos = new DataOutputStream(osToTracker);
        dos.write(1);
        dos.writeByte(Message.MSG_LOGOUT);
    }

    /**
     * write meta file peer to file
     */
    private void writeMetaFilePeerToFile() throws FileNotFoundException {
        System.out.println("Write Meta File");
        PrintWriter pw = new PrintWriter(pathRepo + "/metafile.txt");
        for (int i = 0; i < metaFilesPeer.list.size(); i++) {
            /* parent name sha isFile timeadded */
            pw.print(metaFilesPeer.list.get(i).parent);
            pw.print("##");
            pw.print(metaFilesPeer.list.get(i).name);
            pw.print("##");
            if (metaFilesPeer.list.get(i).isFile) {
                pw.print(1);
                pw.print("##");
                pw.print(Util.convertBytesToBase64(metaFilesPeer.list.get(i).sha));
            } else {
                pw.print(0);
                pw.print("##");
                pw.print(0);
            }

            pw.print("##");
            pw.print(metaFilesPeer.list.get(i).timeAdded);
            pw.println("##");
        }
        pw.close();
    }

    /**
     * write log file to file
     */
    private void writeLogFile(String parent, String name, boolean isfile, byte[] sha, long timeedited, String desc) throws FileNotFoundException {
        System.out.println("Write Log File");

        try {
            FileWriter fstream = new FileWriter("/Users/rifky/tes.txt", true);
            BufferedWriter fbw = new BufferedWriter(fstream);
            fbw.write("append txt...");
            fbw.write(parent);
            fbw.write("##");
            fbw.write(name);
            fbw.write("##");

            if (isfile) {
                fbw.write(1);
                fbw.write("##");
                fbw.write(Util.convertBytesToBase64(sha));
            } else {
                fbw.write(0);
                fbw.write("##");
                fbw.write(0);
            }

            fbw.write("##");
            fbw.write(String.valueOf(timeedited));
            fbw.write("##");
            fbw.write(desc);
            fbw.write("##");
            fbw.newLine();
            fbw.close();
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    /**
     * receive synchronization command from Tracker
     */
    private void receiveSyncCommand() throws IOException {
        syncCmd = new SyncCmd();
        System.out.println("Read Synchronization Command");
        DataInputStream dis = new DataInputStream(isFromTracker);
        Byte code;
        String path1, path2, name1, name2, ipaddress;
        while (true) {
            code = dis.readByte();
            if (code == Message.MSG_NEW_KEY) {
                GUIPeer.RC4KeyByte = Util.convertBase64ToBytes(dis.readUTF());
                RC4KeyByte = GUIPeer.RC4KeyByte;
                break;
            }
            path1 = dis.readUTF();
            path2 = dis.readUTF();
            name1 = dis.readUTF();
            name2 = dis.readUTF();
            ipaddress = dis.readUTF();

            System.out.println(code + path1 + path2 + name1 + name2 + ipaddress);
            syncCmd.addCommand(code, path1, path2, name1, name2, ipaddress);
        }
    }

    /**
     * synchronization make directory
     */
    private void syncMakeDir(Command cmd) {
        File f = new File(pathRepo + cmd.parent1 + cmd.name1);
        f.mkdirs();
    }

    /**
     * synchronization delete
     */
    private void syncDelete(Command cmd) throws Exception {
        File f = new File(pathRepo + cmd.parent1 + cmd.name1);
        if (f.exists()) {
            if (f.isFile()) {
                //writeLogFile(pathRepo + cmd.parent1, pathRepo + cmd.name1, true, Util.getSHA(f), System.currentTimeMillis(), "deleted");
                f.delete();
            } else {
                //writeLogFile(pathRepo + cmd.parent1, pathRepo + cmd.name1, false, null, System.currentTimeMillis(), "deleted");
                delTreeDir(f);
            }
        }       
    }

    /**
     * synchronization rename
     */
    private void syncRename(Command cmd) throws FileNotFoundException {
        File f = new File(pathRepo + cmd.parent1 + cmd.name1);
        //writeLogFile(pathRepo + cmd.parent1, pathRepo + cmd.name1, true, Util.getSHA(f), System.currentTimeMillis(), "renamed");
        f.renameTo(new File(pathRepo + cmd.parent1 + cmd.name2));
    }

    /**
     * synchronization copy
     */
    private void syncCopy(Command cmd) throws Exception {
        File src = new File(pathRepo + cmd.parent1 + cmd.name1);
        File dest = new File(pathRepo + cmd.parent2 + cmd.name1);
        copyFile(src, dest);
    }

    /**
     * synchronization download
     */
    private void syncDownload(Command cmd) throws IOException, Exception {
        System.out.println("Sync Download");
        String[] addressport = cmd.addressPort.split(":");
        connectToPeer(addressport[0], Integer.valueOf(addressport[1]));
        reqFile(cmd.parent1 + cmd.name1);
        receiveFile(cmd.parent1 + cmd.name1);
        disconnectToPeer();
        iHave(cmd.parent1, cmd.name1);
    }

    /**
     * copy file from one folder to another
     */
    private void copyFile(File src, File dest) throws Exception {
        FileInputStream fis = new FileInputStream(src);
        FileOutputStream fos = new FileOutputStream(dest);
        byte[] buf = new byte[4096];
        int len = fis.read(buf);
        while (len != -1) {
            fos.write(buf, 0, len);
            len = fis.read(buf);
        }
        fis.close();
        fos.close();
    }

    /**
     * do synchronization
     */
    private boolean doSync() throws Exception {
        boolean success = true;
        SyncCmd mkdir = new SyncCmd();
        SyncCmd delete = new SyncCmd();
        SyncCmd rename = new SyncCmd();
        SyncCmd copy = new SyncCmd();
        SyncCmd move = new SyncCmd();
        SyncCmd download = new SyncCmd();
        for (int i = 0; i < syncCmd.list.size(); i++) {
            if (syncCmd.list.get(i).code == SyncCmd.MKDIR) { /* make dir command */
                mkdir.addCommand(syncCmd.list.get(i));
            } else if (syncCmd.list.get(i).code == SyncCmd.DELETE) { /* delete command */
                delete.addCommand(syncCmd.list.get(i));
            } else if (syncCmd.list.get(i).code == SyncCmd.RENAME) { /* rename command */
                rename.addCommand(syncCmd.list.get(i));
            } else if (syncCmd.list.get(i).code == SyncCmd.COPY) { /* copy command */
                copy.addCommand(syncCmd.list.get(i));
            } else { /* Download Command */
                download.addCommand(syncCmd.list.get(i));
            }
        }
        doSync(mkdir);
        doSync(rename);
        doSync(copy);
        doSync(move);
        doSync(delete);
        try {
            doSync(download);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            success = false;
        }

        return success;
    }

//    private boolean doSync(SyncCmd syncCmd) throws Exception {
//        System.out.println("DOSYNC");
//        boolean success = true;
//
//        for (int i = 0; i < syncCmd.list.size(); i++) {
//            if (syncCmd.list.get(i).code == SyncCmd.MKDIR) { /* make dir command */
//                syncMakeDir(syncCmd.list.get(i));
//            } else if (syncCmd.list.get(i).code == SyncCmd.DELETE) { /* delete command */
//                syncDelete(syncCmd.list.get(i));
//            } else if (syncCmd.list.get(i).code == SyncCmd.RENAME) { /* rename command */
//                syncRename(syncCmd.list.get(i));
//            } else if (syncCmd.list.get(i).code == SyncCmd.COPY) { /* copy command */
//                syncCopy(syncCmd.list.get(i));
//            } else { /* Download Command */
//                try {
//                    System.out.println("DOWNLOAD");
//                    syncDownload(syncCmd.list.get(i));
//                } catch (Exception e) {
//                    System.out.println(e.getMessage());
//                    success = false;
//                }
//            }
//        }
//
//
//
//        return success;
//    }
    /**
     * do synchronization
     */
    private void doSync(SyncCmd cmd) throws Exception {
        for (int i = 0; i < cmd.list.size(); i++) {
            if (cmd.list.get(i).code == SyncCmd.MKDIR) {
                syncMakeDir(cmd.list.get(i));
            } else if (cmd.list.get(i).code == SyncCmd.DELETE) {
                syncDelete(cmd.list.get(i));
            } else if (cmd.list.get(i).code == SyncCmd.RENAME) {
                syncRename(cmd.list.get(i));
            } else if (cmd.list.get(i).code == SyncCmd.COPY) {
                syncCopy(cmd.list.get(i));
            } else {
                syncDownload(cmd.list.get(i));
            }
        }
    }

    /**
     * read file from other peer
     */
    private void receiveFile(String path2) throws IOException, Exception {
        System.out.println("Receive File from other peer");
        DataInputStream dis = new DataInputStream(isFromPeer);
        int len = dis.readInt();
        byte msg = dis.readByte();
        String path = dis.readUTF();

        /* store in temp */
        File temp = new File(pathRepo + "/" + "temp");
        Communication.readFile(len - 1 - Util.getUTFLength(path) - 8, isFromPeer, temp.getCanonicalPath());

        System.out.println(pathRepo + path);
        /* rename to original path */
        temp.renameTo(new File(pathRepo + path2));

        System.out.println("Success to receive");
    }

    /**
     * send message to tracker that i have already have this file
     */
    private void iHave(String parent, String name) throws IOException {
        System.out.println("Send IHave");
        DataOutputStream dos = new DataOutputStream(osToPeer);
        dos.writeInt(1 + Util.getUTFLength(parent) + Util.getUTFLength(name));
        dos.writeByte(Message.MSG_IHAVE);
        dos.writeUTF(parent);
        dos.writeUTF(name);
    }

    /**
     * Check if RC4Key is changed
     */
    private void checkRC4() throws IOException, Exception {
        System.out.println("Check RC4Key");
        if (!Util.convertBytesToBase64(GUIPeer.RC4KeyByte).equals(Util.convertBytesToBase64(RC4KeyByte))) {
            /* send message to tracker to update RC4Key */
            DataOutputStream dos = new DataOutputStream(osToTracker);
            dos.writeInt(1);
            dos.writeByte(Message.MSG_CHANGE_KEY);
            /* change RC4Key Binding */
            bindingRC4ToStream();
        } else {
            /* do nothing */
        }
    }

    /**
     * send synchronization successful
     */
    private void sendRequestChangeLastUpdate() throws IOException {
        DataOutputStream dos = new DataOutputStream(osToTracker);
        dos.writeInt(1);
        dos.writeByte(Message.MSG_CHANGE_LASTUPDATE);
    }

    private void sendPort() throws IOException {
        System.out.println("Send Port");
        DataOutputStream dos = new DataOutputStream(osToTracker);
        dos.writeByte(Message.MSG_SEND_PORT);
        dos.writeUTF(String.valueOf(GUIPeer.portServerPeer));
    }

    /**
     * send rc4cek to peer to be connected
     */
    private byte RC4Cek() throws IOException {
        System.out.println("Send RC4Cek");
        DataOutputStream dos = new DataOutputStream(osToPeer);
        DataInputStream dis = new DataInputStream(isFromPeer);
        dos.writeInt(1);
        dos.writeByte(Message.MSG_RC4CEK);
        byte rc4cek = dis.readByte();
        return rc4cek;
    }

    /**
     * Pause synchronization
     */
    private void pause() throws IOException {
        DataOutputStream dos = new DataOutputStream(osToTracker);
        dos.writeInt(1);
        dos.writeByte(Message.MSG_PAUSE);
    }

    /**
     * play paused synchronization
     */
    private void play() throws IOException {
        DataOutputStream dos = new DataOutputStream(osToTracker);
        dos.writeInt(1);
        dos.writeByte(Message.MSG_PLAY);
    }
}
