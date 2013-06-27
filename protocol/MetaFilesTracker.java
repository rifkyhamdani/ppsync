package protocol;

import java.util.ArrayList;
import util.Util;

/**
 *
 * @author rifky
 */
public class MetaFilesTracker {
    
    public MetaFilesTracker() {
        list = new ArrayList<MetaFile>();
    }
    
    public ArrayList<MetaFile> list;
    
    public class MetaFile {
        public String parent; /* save path of the file/folder exclude file/folder name*/
        public String name; /* save file name */
        public boolean isFile; /* save type is a file or folder */
        public byte[] sha; /* save sha of the file, null if folder*/
        public long timeAdded; /* save time when file/folder is added to tracker */
        public ArrayList<String> owners; /* save ip address of file owners */
        
        public MetaFile() {
            owners = new ArrayList<String>();
        }
    }
    
    /**
     * get index meta file with specific SHA, return index if true, -1 if not found
     */
    public int getIndexFileWithSHA(byte[] sha) {
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
     * delete meta file with index i from list
     */
    public void delMetaFile(int i) {
        this.list.remove(i);
    }
    
    /**
     * add meta file
     */
    public void addMetaFile(MetaFile mf) {
        list.add(mf);
    }
    
    /**
     * add meta file to list
     */
    public void addMetaFile(String parent, String name, boolean isfile, byte[] sha, long timeadded, String owner) {
        MetaFile mf = new MetaFile();
        mf.parent = parent;
        mf.name = name;
        mf.isFile = isfile;
        mf.sha = sha;
        mf.timeAdded = timeadded;
        mf.owners.add(owner);
        list.add(mf);
    }
    
    /**
     * get index meta file with path, return -1 if not found
     */
    public int getIndexMetaFileWithPath(String parent, String name) {
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).parent.equals(parent) && list.get(i).name.equals(name)) {
                return i;
            }
        }
        return -1;
    }
}
