package peer;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.UnknownHostException;

/**
 *
 * @author rifky
 */
public class Test {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws FileNotFoundException, UnknownHostException, IOException, Exception {
        int Min = 0, Max = 9;
        System.out.println(Math.random());
        int res = Min + (int)(Math.random() * ((Max - Min) + 1));
        System.out.println(res);
    }
}
