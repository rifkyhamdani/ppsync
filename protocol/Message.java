package protocol;

/**
 *
 * @author rifky
 */
public class Message {
    
    public static String Identifier = "p2psynchronization";
    public static byte SUCCESS_AUTH = 1;
    public static byte FAILED_AUTH = 51;
    public static byte ERROR_MESSAGE = 99;
    
    /* message id */
    public static byte MSG_HANDSHAKE = 0;
    public static byte MSG_AUTH = 1;
    public static byte MSG_RESP_AUTH = 2;
    public static byte MSG_LOGOUT = 3;
    public static byte MSG_SEND_INITIAL_KEY = 4;
    public static byte MSG_SEND_KEY = 5;
    public static byte MSG_SEND_LIST = 6;
    public static byte MSG_SEND_SYNC = 7;
    public static byte MSG_REQ_FILE = 8;
    public static byte MSG_SEND_FILE = 9;
    public static byte MSG_SYNC = 10;
    public static byte MSG_IHAVE = 11;
    public static byte MSG_SEND_META = 12; 
    public static byte MSG_NEW_KEY = 13;
    public static byte MSG_CHANGE_KEY = 14;
    public static byte MSG_CHANGE_LASTUPDATE = 15;
    public static byte MSG_SEND_PORT = 16;
    public static byte MSG_RC4CEK = 17;
    public static byte MSG_PAUSE = 18;
    public static byte MSG_PLAY = 19;
    
    /* Synchronization */
    public static byte SYNC_MAKE_DIR = 1;
    public static byte SYNC_DEL = 2;
    public static byte SYNC_RENAME = 3;
    public static byte SYNC_MOVE = 4;
    public static byte SYNC_DOWNLOAD = 5;
    
    public static byte MSG_ERROR_STATUS = 99;
}
