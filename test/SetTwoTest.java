import org.junit.Test;

import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class SetTwoTest {

    @Test
    public void challenge_nine() {
        byte[] key1 = "YELLOW SUBMARINE".getBytes(StandardCharsets.US_ASCII);
        byte[] key2 = "YELLOW SUBMARIN".getBytes(StandardCharsets.US_ASCII);
        byte[] response = SetTwo.PKCS7Padding(key1, 20);
        assertEquals("YELLOW SUBMARINE\4\4\4\4", new String(response, StandardCharsets.US_ASCII));
        byte[] response2 = SetTwo.PKCS7Padding(key2, 20);
        assertEquals("YELLOW SUBMARIN\5\5\5\5\5", new String(response2, StandardCharsets.US_ASCII));
    }

    @Test
    public void challenge_ten() throws Exception {
        String encryptedBase64 = new String(Files.readAllBytes(Paths.get("files/10.txt"))).replaceAll("[\n\r]", "");;
        byte[] encryptedBytes = Base64.decodeBase64(encryptedBase64);
        byte[] key = "YELLOW SUBMARINE".getBytes(StandardCharsets.UTF_8);
        byte[] iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".getBytes(StandardCharsets.US_ASCII);
        String response = SetTwo.decryptCBC(encryptedBytes, key, iv);
        System.out.println(response);
    }
}
