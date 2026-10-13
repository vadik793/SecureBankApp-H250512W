// Author: Kudzaishe Andrea | Reg No: H250512W | Secure Banking Application
import java.util.List;

/** Abstraction (Unit 2): the rest of the program depends on this interface, not on how data is stored. */
public interface DataStore {
    List<String> readLines(String name);
    void writeLines(String name, List<String> lines);
    void appendLine(String name, String line);
}
