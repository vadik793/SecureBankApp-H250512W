
import java.util.List;


public interface DataStore {
    List<String> readLines(String name);
    void writeLines(String name, List<String> lines);
    void appendLine(String name, String line);
}
