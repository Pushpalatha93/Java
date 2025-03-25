import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class BlowfishEncryption {

    private static final String ALGORITHM = "Blowfish";

    public static byte[] encrypt(String key, String data) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(String key, byte[] encryptedData) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }

    public static void main(String[] args) {
        try {
            String key = "Javacodegeeks";
            String data = "Hello, world!";

            // Encrypt data
            byte[] encryptedData = BlowfishEncryption.encrypt(key, data);
            System.out.println("Encrypted data: " + new String(encryptedData));

            // Decrypt data
            String decryptedData = BlowfishEncryption.decrypt(key, encryptedData);
            System.out.println("Decrypted data: " + decryptedData);
        } catch (Exception e) {
        }
    }
}
