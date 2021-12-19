import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FileInformation {
    private File file;
    private String hash;
    private List<String> titles = new ArrayList<>();
    private List<String> keywords = new ArrayList<>();
    private List<String> descriptions = new ArrayList<>();
    private Map<String, Integer> containingNodes = new HashMap<>();

    public FileInformation(File file, String hostIp, int hostPort) throws NoSuchAlgorithmException, IOException {
        this.setFile(file);
        MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");
        this.setHash(checksum(shaDigest, file));
        this.addTitle(file.getName());
        this.addContainingNode(hostIp, hostPort);
    }

    public File getFile() {
        return file;
    }

    public void setFile(File file) {
        this.file = file;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public List<String> getTitles() {
        return titles;
    }

    public void addTitle(String title) {
        this.titles.add(title);
    }

    public void setTitles(List<String> titles) {
        this.titles = titles;
    }

    public List<String> getKeywords() {
        return keywords;
    }

    public void addKeyword(String keyword) {
        this.keywords.add(keyword);
    }

    public void setKeywords(List<String> keywords) {
        this.keywords = keywords;
    }

    public List<String> getDescriptions() {
        return descriptions;
    }

    public void addDescription(String description) {
        this.descriptions.add(description);
    }

    public void setDescriptions(List<String> descriptions) {
        this.descriptions = descriptions;
    }

    public Map<String, Integer> getContainingNodes() {
        return containingNodes;
    }

    public void addContainingNode(String hostIp, int hostPort) {
        this.containingNodes.put(hostIp, hostPort);
    }

    public void setContainingNodes(Map<String, Integer> containingNodes) {
        this.containingNodes = containingNodes;
    }

    public String searchByAttribute(String attribute, String value) {
        switch(attribute) {
            case "hash":
                if(getHash().equals(value)) {
                    return getHash();
                }
                break;
            case "titles":
                if(getTitles().contains(value)) {
                    return getHash();
                }
                break;
            case "keywords":
                if(getKeywords().contains(value)) {
                    return getHash();
                }
                break;
            case "descriptions":
                if(getDescriptions().contains(value)) {
                    return getHash();
                }
        }
        return null;
    }

    private String checksum(MessageDigest digest, File file) throws IOException {
        FileInputStream fis = new FileInputStream(file);

        byte[] byteArray = new byte[1024];
        int bytesCount = 0;

        while ((bytesCount = fis.read(byteArray)) != -1)
        {
            digest.update(byteArray, 0, bytesCount);
        };

        fis.close();

        byte[] bytes = digest.digest();
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < bytes.length; i++) {
            sb.append(Integer
                    .toString((bytes[i] & 0xff) + 0x100, 16)
                    .substring(1));
        }

        return sb.toString();
    }
}
