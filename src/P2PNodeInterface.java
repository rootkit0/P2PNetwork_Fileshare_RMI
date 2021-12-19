import java.io.File;
import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public interface P2PNodeInterface extends Remote {
    void registerNode(P2PNodeInterface node) throws RemoteException;
    void notifyNode(P2PNodeInterface node) throws RemoteException;

    String getUid() throws RemoteException;
    void uploadFile(File file) throws IOException, NoSuchAlgorithmException;
    Map<String, FileInformation> listFiles() throws IOException, NoSuchAlgorithmException;
    //void editFile(String fileHash, FileInformation fileInformation);
}
