import org.junit.Test;

import org.apache.commons.codec.binary.Base64;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.Assert.assertEquals;

public class SetTwoTest {

    private static String convertCrlfsToLfs(String crlfString) {
        return crlfString.replaceAll("\\r\\n?", "\n");
    }

    private static boolean isCrlfSystem() {
        String s = System.lineSeparator();
        return s.equals("\r\n");
    }

    @Test
    public void challenge_nine() {
        byte[] key1 = "YELLOW SUBMARINE".getBytes(StandardCharsets.US_ASCII);
        byte[] key2 = "YELLOW SUBMARIN".getBytes(StandardCharsets.US_ASCII);
        byte[] response = SetTwo.padPKCS7(key1, 20);
        assertEquals("YELLOW SUBMARINE\4\4\4\4", new String(response, StandardCharsets.US_ASCII));
        byte[] response2 = SetTwo.padPKCS7(key2, 20);
        assertEquals("YELLOW SUBMARIN\5\5\5\5\5", new String(response2, StandardCharsets.US_ASCII));
    }

    @Test
    public void challenge_ten_encrypt() throws Exception {
        String plainText = new String(Files.readAllBytes(Paths.get("files/10_pt.txt")));
        plainText = isCrlfSystem() ? convertCrlfsToLfs(plainText) : plainText;
        byte[] plainTextBytes = plainText.getBytes(StandardCharsets.US_ASCII);
        byte[] key = "YELLOW SUBMARINE".getBytes(StandardCharsets.US_ASCII);
        byte[] iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".getBytes(StandardCharsets.US_ASCII);
        String response = SetTwo.encryptCBC(plainTextBytes, key, iv);
        String expected = new String(Files.readAllBytes(Paths.get("files/10.txt"))).replaceAll("[\n\r]", "");
        assertEquals(expected, response);
    }

    @Test
    public void challenge_ten_decrypt() throws Exception {
        String encryptedBase64 = new String(Files.readAllBytes(Paths.get("files/10.txt")));
        byte[] encryptedBytes = Base64.decodeBase64(encryptedBase64);
        byte[] key = "YELLOW SUBMARINE".getBytes(StandardCharsets.UTF_8);
        byte[] iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".getBytes(StandardCharsets.US_ASCII);
        String response = SetTwo.decryptCBC(encryptedBytes, key, iv);
        String expected = new String(Files.readAllBytes(Paths.get("files/10_pt.txt")));
        expected = isCrlfSystem() ? convertCrlfsToLfs(expected) : expected;
        assertEquals(expected, response);
    }
}
