import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;

public class SetTwo {

    public static byte[] padPKCS7(byte[] bytes, int blockSize) {
        int mod = bytes.length % blockSize;
        int bytesToPad = (mod != 0) ? (blockSize - mod) : 0;
        byte[] paddedBytes = new byte[bytes.length + bytesToPad];
        for (int i = 0; i < bytes.length; i++) {
            paddedBytes[i] = bytes[i];
        }
        for (int i = 0; i < bytesToPad; i++) {
            paddedBytes[bytes.length + i] = (byte) bytesToPad;
        }
        return paddedBytes;
    }

    public static byte[] unpadPKCS7(byte[] bytes, int blockSize) {
        int padChar = (int) bytes[bytes.length - 1];
        if (padChar <= 0 || padChar >= blockSize) {
            return bytes;
        }
        return Arrays.copyOfRange(bytes, 0, bytes.length - padChar);
    }

    private static byte[] decryptAesEcbModeBytes(byte[] encryptedBytes, byte[] key) throws Exception {
        Key aesKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        return cipher.doFinal(encryptedBytes);
    }

    private static byte[] encryptAesEcbModeBytes(byte[] plainTextBytes, byte[] key) throws Exception {
        Key aesKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return cipher.doFinal(plainTextBytes);
    }

    public static String decryptCBC(byte[] cipherBytes, byte[] key, byte[] iv) throws Exception {
        int blockSize = key.length;
        byte[] cipherKeyDecryptBytes = decryptAesEcbModeBytes(cipherBytes, key);
        byte[] plainTextBytes = new byte[cipherBytes.length];

        byte[] firstAesDecryptBlock = Arrays.copyOfRange(cipherKeyDecryptBytes, 0, blockSize);
        byte[] firstPtBlock = SetOne.getXorBytes(firstAesDecryptBlock, iv);
        for (int i = 0; i < blockSize; i++) {
            plainTextBytes[i] = firstPtBlock[i];
        }

        for (int i = blockSize; i < cipherBytes.length; i += blockSize) {
            byte[] decryptedBlock = Arrays.copyOfRange(cipherKeyDecryptBytes, i, i + blockSize);
            byte[] previousCipherBlock = Arrays.copyOfRange(cipherBytes, i - blockSize, i);
            byte[] ptBlock = SetOne.getXorBytes(decryptedBlock, previousCipherBlock);
            for (int j = 0; j < blockSize; j++) {
                plainTextBytes[i + j] = ptBlock[j];
            }
        }

        return new String(unpadPKCS7(plainTextBytes, blockSize), StandardCharsets.US_ASCII);
    }

    public static String encryptCBC(byte[] plainTextBytes, byte[] key, byte[] iv) throws Exception {
        int blockSize = key.length;
        byte[] paddedPtBytes = padPKCS7(plainTextBytes, blockSize);
        byte[] cipherTextBytes = new byte[paddedPtBytes.length];

        byte[] firstPtBlock = Arrays.copyOfRange(paddedPtBytes, 0, blockSize);
        byte[] firstXorBlock = SetOne.getXorBytes(firstPtBlock, iv);
        byte[] firstCtBlock = encryptAesEcbModeBytes(firstXorBlock, key);
        for (int i = 0; i < blockSize; i++) {
            cipherTextBytes[i] = firstCtBlock[i];
        }

        for (int i = blockSize; i < paddedPtBytes.length; i += blockSize) {
            byte[] currentPtBlock = Arrays.copyOfRange(paddedPtBytes, i, i + blockSize);
            byte[] previousCtBlock = Arrays.copyOfRange(cipherTextBytes, i - blockSize, i);
            byte[] xorBlock = SetOne.getXorBytes(currentPtBlock, previousCtBlock);
            byte[] currentCtBlock = encryptAesEcbModeBytes(xorBlock, key);
            for (int j = 0; j < blockSize; j++) {
                cipherTextBytes[i + j] = currentCtBlock[j];
            }
        }

        return Base64.encodeBase64String(cipherTextBytes);
    }
}
