import java.io.*;
import java.nio.file.Files;
import java.rmi.AccessException;
import java.rmi.AlreadyBoundException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class P2PNode extends UnicastRemoteObject implements P2PNodeInterface {
    //Global class vars
    private static String uid;
    private static int clientPort;
    private static File folderPath;
    private static String hostIp;
    private static int hostPort;
    //Read from keyboard
    private static InputStreamReader ir = new InputStreamReader(System.in);
    private static BufferedReader br = new BufferedReader(ir);
    //Connected nodes
    List<P2PNodeInterface> connectedNodes = new ArrayList<>();
    //Available files
    Map<String, FileInformation> networkFiles = new HashMap<>();

    public P2PNode() throws RemoteException {
        uid = UUID.randomUUID().toString();
    }

    public static void main(String args[]) throws IOException, NoSuchAlgorithmException {
        P2PNode node = new P2PNode();
        //Treat args
        if(args.length == 2) {
            clientPort = Integer.parseInt(args[0]);
            folderPath = new File(args[1]);
            if(folderPath.exists() && folderPath.isDirectory()) {
                node.readFiles();
                node.isolatedTask(node);
            }
        }
        else if (args.length == 4 && isValidIPAddress(args[2])) {
            clientPort = Integer.parseInt(args[0]);
            folderPath = new File(args[1]);
            hostIp = args[2];
            hostPort = Integer.parseInt(args[3]);
            if(folderPath.exists() && folderPath.isDirectory()) {
                node.readFiles();
                node.connectedTask(node);
                node.isolatedTask(node);
            }
        }
        else {
            System.err.println("Execute the program as:");
            System.err.println("./P2PNode client_port folder_path [host_ip] [host_port]");
        }
    }

    public static boolean isValidIPAddress(String ip) {
        if (ip == null) {
            return false;
        }
        String IPV4_REGEX = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
        Pattern IPV4_PATTERN = Pattern.compile(IPV4_REGEX);
        Matcher matcher = IPV4_PATTERN.matcher(ip);
        return matcher.matches();
    }

    public void readFiles() throws NoSuchAlgorithmException, IOException {
        for(File fileEntry : Objects.requireNonNull(folderPath.listFiles())) {
            if(fileEntry.isDirectory()) {
                readFiles();
            }
            else {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                String hash = this.checksum(digest, fileEntry);
                FileInformation fileInfo = new FileInformation(fileEntry, hostIp, hostPort);
                networkFiles.put(hash, fileInfo);
            }
        }
    }

    private String checksum(MessageDigest digest, File file) throws IOException {
        FileInputStream fis = new FileInputStream(file);

        byte[] byteArray = new byte[1024];
        int bytesCount = 0;

        while((bytesCount = fis.read(byteArray)) != -1) {
            digest.update(byteArray, 0, bytesCount);
        }

        fis.close();

        byte[] bytes = digest.digest();
        StringBuilder sb = new StringBuilder();

        for(int i = 0; i < bytes.length; i++) {
            sb.append(Integer
                    .toString((bytes[i] & 0xff) + 0x100, 16)
                    .substring(1));
        }

        return sb.toString();
    }

    //Server
    public void isolatedTask(P2PNode node) {
        try {
            Registry registry = startRegistry(clientPort);
            registry.bind("node", (P2PNode) this);
            System.out.println("Starting node at port " + clientPort);
            this.fileshareActions(node);
        } catch (AlreadyBoundException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    //Client
    public void connectedTask(P2PNode node) {
        try {
            Registry registry = LocateRegistry.getRegistry(hostIp, hostPort);
            P2PNodeInterface stub = (P2PNodeInterface) registry.lookup("node");
            stub.registerNode(node);
            this.notifyNodes(node);
            System.out.println("Connected to the host with IP: " + hostIp + " and port: " + hostPort);
        } catch (NotBoundException | RemoteException e) {
            e.printStackTrace();
        }
    }

    private Registry startRegistry(int clientPort) throws RemoteException {
        try {
            //Check if registry is already created
            Registry registry = LocateRegistry.getRegistry(clientPort);
            registry.list();
            return registry;
        }
        catch(RemoteException re) {
            //Create registry if not already
            return LocateRegistry.createRegistry(clientPort);
        }
    }

    public void notifyNodes(P2PNodeInterface node) throws RemoteException {

        for(P2PNodeInterface node_iter: connectedNodes) {
            node_iter.notifyNode(node);
        }
    }

    public void fileshareActions(P2PNodeInterface node) throws IOException, NoSuchAlgorithmException {
        System.out.println("Welcome to the P2P network, choose one option:");
        while (true) {
            System.out.println( "1 - Upload file\n" +
                                "2 - Download file\n" +
                                "3 - List files\n" +
                                "4 - Search files\n" +
                                "5 - Edit file\n" +
                                "6 - Disconnect\n");
            int userAction = Integer.parseInt(br.readLine());
            switch (userAction) {
                case 1 -> uploadFile(node);
                case 2 -> downloadFile(node);
                case 3 -> listFiles(node);
                case 4 -> searchFilesLocal(node);
                case 5 -> editFile(node);
                case 6 -> disconnect();
            }
        }
    }

    public void uploadFile(P2PNodeInterface node) throws IOException, NoSuchAlgorithmException {
        System.out.println("Enter the full path of the file you want to upload:");
        String filePath = br.readLine();
        File file = new File(filePath);
        if(file.exists() && file.isFile()) {
            //Locally
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String hash = this.checksum(digest, file);
            FileInformation fileInfo = new FileInformation(file, hostIp, hostPort);
            this.networkFiles.put(hash, fileInfo);
            //Entire network
            for(P2PNodeInterface node_iter: connectedNodes) {
                node_iter.uploadFile(file);
            }
            System.out.println("File uploaded!");
        }
        else {
            System.out.println("Invalid file path!");
        }
    }

    public void listFiles(P2PNodeInterface node) throws IOException, NoSuchAlgorithmException {
        System.out.println("----- Local files: -----");
        for(Map.Entry<String, FileInformation> entry : networkFiles.entrySet()) {
            System.out.println("* File: " + entry.getValue().getHash());
            System.out.println("File titles: " + entry.getValue().getTitles());
            System.out.println("File keywords: " + entry.getValue().getKeywords());
            System.out.println("File descriptions: " + entry.getValue().getDescriptions());
        }
        System.out.println("----- Network files: -----");
        for(P2PNodeInterface node_iter : connectedNodes) {
            System.out.println("Files from node: " + node_iter.getUid());
            for(Map.Entry<String, FileInformation> entry : node_iter.listFiles().entrySet()) {
                System.out.println("* File: " + entry.getValue().getHash());
                System.out.println("File titles: " + entry.getValue().getTitles());
                System.out.println("File keywords: " + entry.getValue().getKeywords());
                System.out.println("File descriptions: " + entry.getValue().getDescriptions());
            }
        }
    }

    public List<String> searchFilesLocal(P2PNodeInterface node) throws IOException, NoSuchAlgorithmException {
        List<String> resultFiles = new ArrayList<>();
        System.out.println("Select the attribute you want to search by:");
        System.out.println("1 - Hash");
        System.out.println("2 - Titles");
        System.out.println("3 - Keywords");
        System.out.println("4 - Descriptions");
        int attribute = Integer.parseInt(br.readLine());
        String value = "";
        switch (attribute) {
            case 1 -> {
                System.out.println("Enter the hash value you want to search for:");
                value = br.readLine();
                for (Map.Entry<String, FileInformation> entry : networkFiles.entrySet()) {
                    String hashResult = entry.getValue().searchByAttribute("hash", value);
                    if (hashResult != null) {
                        resultFiles.add(hashResult);
                    }
                }
            }
            case 2 -> {
                System.out.println("Enter the title value you want to search for:");
                value = br.readLine();
                for (Map.Entry<String, FileInformation> entry : networkFiles.entrySet()) {
                    String hashResult = entry.getValue().searchByAttribute("titles", value);
                    if (hashResult != null) {
                        resultFiles.add(hashResult);
                    }
                }
            }
            case 3 -> {
                System.out.println("Enter the keyword value you want to search for:");
                value = br.readLine();
                for (Map.Entry<String, FileInformation> entry : networkFiles.entrySet()) {
                    String hashResult = entry.getValue().searchByAttribute("keywords", value);
                    if (hashResult != null) {
                        resultFiles.add(hashResult);
                    }
                }
            }
            case 4 -> {
                System.out.println("Enter the description value you want to search for:");
                value = br.readLine();
                for (Map.Entry<String, FileInformation> entry : networkFiles.entrySet()) {
                    String hashResult = entry.getValue().searchByAttribute("descriptions", value);
                    if (hashResult != null) {
                        resultFiles.add(hashResult);
                    }
                }
            }
        }
        System.out.println("List of found files with attribute " + attribute + " and value " + value);
        System.out.println(resultFiles);
        return resultFiles;
    }

    public Map<String, String> searchFilesNetwork(P2PNodeInterface node) throws IOException, NoSuchAlgorithmException {
        Map<String, String> resultFilesPerNode = new HashMap<>();
        System.out.println("Select the attribute you want to search by:");
        System.out.println("1 - Hash");
        System.out.println("2 - Titles");
        System.out.println("3 - Keywords");
        System.out.println("4 - Descriptions");
        int attribute = Integer.parseInt(br.readLine());
        String value = "";
        switch (attribute) {
            case 1 -> {
                System.out.println("Enter the hash value you want to search for:");
                value = br.readLine();
                for(P2PNodeInterface node_iter : connectedNodes) {
                    for (Map.Entry<String, FileInformation> entry : node_iter.listFiles().entrySet()) {
                        String hashResult = entry.getValue().searchByAttribute("hash", value);
                        if (hashResult != null) {
                            resultFilesPerNode.put(node_iter.getUid(), hashResult);
                        }
                    }
                }
            }
            case 2 -> {
                System.out.println("Enter the title value you want to search for:");
                value = br.readLine();
                for(P2PNodeInterface node_iter : connectedNodes) {
                    for (Map.Entry<String, FileInformation> entry : node_iter.listFiles().entrySet()) {
                        String hashResult = entry.getValue().searchByAttribute("titles", value);
                        if (hashResult != null) {
                            resultFilesPerNode.put(node_iter.getUid(), hashResult);
                        }
                    }
                }
            }
            case 3 -> {
                System.out.println("Enter the keyword value you want to search for:");
                value = br.readLine();
                for(P2PNodeInterface node_iter : connectedNodes) {
                    for (Map.Entry<String, FileInformation> entry : node_iter.listFiles().entrySet()) {
                        String hashResult = entry.getValue().searchByAttribute("keywords", value);
                        if (hashResult != null) {
                            resultFilesPerNode.put(node_iter.getUid(), hashResult);
                        }
                    }
                }
            }
            case 4 -> {
                System.out.println("Enter the description value you want to search for:");
                value = br.readLine();
                for(P2PNodeInterface node_iter : connectedNodes) {
                    for (Map.Entry<String, FileInformation> entry : node_iter.listFiles().entrySet()) {
                        String hashResult = entry.getValue().searchByAttribute("descriptions", value);
                        if (hashResult != null) {
                            resultFilesPerNode.put(node_iter.getUid(), hashResult);
                        }
                    }
                }
            }
        }

        for(P2PNodeInterface node_iter : connectedNodes) {
            System.out.println("Showing search result for node: " + node_iter.getUid());
            System.out.println("List of found files with attribute " + attribute + " and value " + value);
            System.out.println(resultFilesPerNode.get(node_iter.getUid()));
        }

        return resultFilesPerNode;
    }

    public void downloadFile(P2PNodeInterface node) throws IOException, NoSuchAlgorithmException {
        System.out.println("Search the file/s you want to download:");
        List<String> filesToDownload = this.searchFilesLocal(this);
        for(String fileHash : filesToDownload) {
            FileInformation fileInfo = networkFiles.get(fileHash);
            String fileName = fileInfo.getFile().getName();
            //Download file content (only local)
            byte[] fileContent = Files.readAllBytes(fileInfo.getFile().toPath());
            //Write downloaded file to local path
            File newFile = new File(folderPath.getAbsolutePath() + "\\" + fileName);
            FileOutputStream fos = new FileOutputStream(newFile);
            fos.write(fileContent);
            fos.flush();
            fos.close();
            System.out.println("File " + fileName + " downloaded!");
        }
    }

    public void editFile(P2PNodeInterface node) throws IOException, NoSuchAlgorithmException {
        System.out.println("Search the file/s you want to edit:");
        List<String> filesToEdit = this.searchFilesLocal(this);
        for(String fileHash : filesToEdit) {
            FileInformation fileInfo = networkFiles.get(fileHash);
            System.out.println("Select the attribute you want to add content to:");
            System.out.println("1 - Titles");
            System.out.println("2 - Keywords");
            System.out.println("3 - Descriptions");
            int attribute = Integer.parseInt(br.readLine());
            String value = "";
            switch (attribute) {
                case 1:
                    System.out.println("Enter the title you want to add:");
                    value = br.readLine();
                    fileInfo.addTitle(value);
                    break;
                case 2:
                    System.out.println("Enter the keyword you want to add:");
                    value = br.readLine();
                    fileInfo.addKeyword(value);
                    break;
                case 3:
                    System.out.println("Enter the description you want to add:");
                    value = br.readLine();
                    fileInfo.addDescription(value);
                    break;
            }

            //Locally
            networkFiles.replace(fileHash, fileInfo);
            //Entire network
            for(P2PNodeInterface node_iter : connectedNodes) {
                node_iter.editFile(fileHash, fileInfo);
            }

            System.out.println("The current content for the file is:");
            System.out.println("File titles: " + fileInfo.getTitles());
            System.out.println("File keywords: " + fileInfo.getKeywords());
            System.out.println("File descriptions: " + fileInfo.getDescriptions());
        }
    }

    public void disconnect() {
        System.exit(0);
    }

    @Override
    public void registerNode(P2PNodeInterface node) throws RemoteException {
        System.out.println("Registering client node");
        this.connectedNodes.add(node);
    }

    @Override
    public void notifyNode(P2PNodeInterface node) throws RemoteException {
        System.out.println("The node with id: " + node.getUid() + " has been added to the network");
        System.out.println("It's files are available right now!");
    }

    @Override
    public String getUid() throws RemoteException {
        return uid;
    }

    @Override
    public void uploadFile(File file) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String hash = this.checksum(digest, file);
        FileInformation fileInfo = new FileInformation(file, hostIp, hostPort);
        this.networkFiles.put(hash, fileInfo);
    }

    @Override
    public Map<String, FileInformation> listFiles() {
        return this.networkFiles;
    }

    @Override
    public void editFile(String fileHash, FileInformation fileInformation) {
        this.networkFiles.replace(fileHash, fileInformation);
    }
}
