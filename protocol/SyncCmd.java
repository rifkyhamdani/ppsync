/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package protocol;

import java.util.ArrayList;

/**
 *
 * @author rifky
 */
public class SyncCmd {

    public SyncCmd() {
        list = new ArrayList<Command>();
    }
    public static byte MKDIR = 0;
    public static byte DELETE = 1;
    public static byte RENAME = 2;
    public static byte COPY = 3;
    public static byte DOWNLOAD = 4;

    public class Command {

        public byte code;
        public String parent1;
        public String parent2;
        public String name1;
        public String name2;
        public String addressPort;
    }
    public ArrayList<Command> list;

    /**
     * add Command
     */
    public void addCommand(byte code, String parent1, String parent2, String name1, String name2, String ipaddress) {
        Command cmd = new Command();
        cmd.code = code;
        cmd.parent1 = parent1;
        cmd.parent2 = parent2;
        cmd.name1 = name1;
        cmd.name2 = name2;
        cmd.addressPort = ipaddress;
        list.add(cmd);
    }

    /**
     * add Command to list
     */
    public void addCommand(Command cmd) {
        list.add(cmd);
    }
}
