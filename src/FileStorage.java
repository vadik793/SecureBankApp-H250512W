
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;


public class FileStorage implements DataStore {
    private final Path dir;

    public FileStorage(String directory) {
        this.dir = Paths.get(directory);
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new StorageException();
        }
    }

    @Override
    public List<String> readLines(String fileName) {
        Path file = dir.resolve(fileName);
        if (!Files.exists(file)) return new ArrayList<>();
        try {
            List<String> out = new ArrayList<>();
            for (String l : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (!l.isBlank()) out.add(l);
            }
            return out;
        } catch (IOException e) {
            throw new StorageException();
        }
    }


    @Override
    public synchronized void writeLines(String fileName, List<String> lines) {
        Path file = dir.resolve(fileName);
        Path tmp = dir.resolve(fileName + ".tmp");
        try {
            Files.write(tmp, lines, StandardCharsets.UTF_8);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new StorageException();
        }
    }

    @Override
    public synchronized void appendLine(String fileName, String line) {
        try {
            Files.write(dir.resolve(fileName), List.of(line), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new StorageException();
        }
    }
}
