import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class SetTwo {

    public static byte[] PKCS7Padding(byte[] bytes, int blockSize) {
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

    public static byte[] decryptAesEcbModeBytes(byte[] encryptedBytes, byte[] key) throws Exception {
        Key aesKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        return cipher.doFinal(encryptedBytes);
    }

    public static String decryptCBC(byte[] cipherBytes, byte[] key, byte[] iv) throws Exception {
        int blockSize = key.length;
        byte[] cipherKeyDecryptBytes = decryptAesEcbModeBytes(cipherBytes, key);
        byte[] plainTextBytes = new byte[cipherBytes.length];

        byte[] firstPtBlock = Arrays.copyOfRange(cipherKeyDecryptBytes, 0, blockSize);
        firstPtBlock = Arrays.copyOfRange(firstPtBlock, 0, blockSize);
        firstPtBlock = SetOne.getXorBytes(firstPtBlock, iv);
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

        return new String(plainTextBytes, StandardCharsets.US_ASCII);
    }
}
