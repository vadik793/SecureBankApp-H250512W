
import java.util.*;


public class InMemoryStore implements DataStore {
    private final Map<String, List<String>> files = new HashMap<>();
    public boolean failWrites = false;

    @Override
    public List<String> readLines(String name) {
        return new ArrayList<>(files.getOrDefault(name, new ArrayList<>()));
    }

    @Override
    public void writeLines(String name, List<String> lines) {
        if (failWrites) throw new StorageException();
        files.put(name, new ArrayList<>(lines));
    }

    @Override
    public void appendLine(String name, String line) {
        if (failWrites) throw new StorageException();
        files.computeIfAbsent(name, k -> new ArrayList<>()).add(line);
    }


    public void replaceLine(String name, int index, String newLine) {
        files.get(name).set(index, newLine);
    }
}
