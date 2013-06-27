package protocol;

import java.util.ArrayList;
import util.Util;

/**
 *
 * @author rifky
 */
public class MetaFilesPeer {

    public ArrayList<MetaFile> list; /* save list of metafile */


    /**
     * Constructor
     */
    public MetaFilesPeer() {
        list = new ArrayList<MetaFile>();
    }

    /**
     * meta file of every file
     */
    public class MetaFile {
        public String parent; /* save path of the file/folder exclude file/folder name*/
        public String name; /* save the name of the file/folder */
        public boolean isFile; /* save type is a file or folder */
        public byte[] sha; /* save sha of the file, null if folder*/
        public long timeAdded; /* save time when file added */

    }

    /**
     * add meta file to list
     */
    public void addMetaFile(String parent, String name, boolean isfile, byte[] sha, long timeadded) {
        MetaFile mf = new MetaFile();
        mf.parent = parent;
        mf.name = name;
        mf.isFile = isfile;
        mf.sha = sha;
        mf.timeAdded = timeadded;
        list.add(mf);
    }

    /**
     * add meta file
     */
    public void addMetaFile(MetaFile mf) {
        this.list.add(mf);
    }

    /**
     * delete meta file with index i from list
     */
    public void delMetaFile(int i) {
        this.list.remove(i);
    }

    /**
     * get file with specific SHA return index of meta file if true -1 if false
     */
    public int getIndexMetaFileWithSHA(byte[] sha) {
        for (int i = 0; i < this.list.size(); i++) {
            if (this.list.get(i).isFile) {
                if (Util.compareBytes(this.list.get(i).sha, sha)) {
                    return i;
                }
            }
        }
        return -1;
    }

    /**
     * get index meta file with specific path return index of meta file if true -1 if false
     */
    public int getIndexMetaFileWithPath(String parent, String name) {
        for (int i = 0; i < this.list.size(); i++) {
            if (this.list.get(i).parent.equals(parent) && this.list.get(i).name.equals(name)) {
                return i;
            }
        }
        return -1;
    }
}
