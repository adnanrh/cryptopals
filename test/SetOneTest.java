import org.junit.Test;

import org.apache.commons.codec.binary.Base64;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class SetOneTest {

    @Test
    public void challenge_one() throws Exception {
        String expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        String actual = SetOne.hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        assertEquals(expected, actual);
    }

    @Test
    public void challenge_two() throws Exception {
        String expected = "746865206b696420646f6e277420706c6179";
        String actual = SetOne.hexXor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965");
        assertEquals(expected, actual);
    }

    @Test
    public void challenge_three() throws Exception {
        String expectedKey = "X";
        String expectedMessage = "Cooking MC's like a pound of bacon";
        List<String> response = SetOne.findSingleXorCipherAndMessage("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        assertEquals(expectedKey, response.get(0));
        assertEquals(expectedMessage, response.get(1));
    }

    @Test
    public void challenge_four() throws Exception {
        String expectedString = "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f";
        String expectedMessage = "Now that the party is jumping";
        List<String> response = SetOne.findEncryptedStringFromFile("files/4.txt");
        assertEquals(expectedString, response.get(0));
        assertEquals(expectedMessage, response.get(1).trim());
    }

    @Test
    public void challenge_five() throws Exception {
        String message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        String key = "ICE";
        String expectedEncrypted = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
                "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        String actualEncrypted = SetOne.encryptWithRepeatingKeyXor(message, key);
        assertEquals(expectedEncrypted, actualEncrypted);
    }

    @Test
    public void challenge_six() throws Exception {
        String encryptedBase64 = new String(Files.readAllBytes(Paths.get("files/6.txt")));
        String expectedKey = "Terminator X: Bring the noise";
        List<String> response = SetOne.findRepeatingXorCipherAndMessage(encryptedBase64);
        assertEquals(expectedKey, response.get(0));
    }

    @Test
    public void challenge_seven() throws Exception {
        String encryptedBase64 = new String(Files.readAllBytes(Paths.get("files/7.txt")));
        String response = SetOne.decryptAesEcbMode(Base64.decodeBase64(encryptedBase64), "YELLOW SUBMARINE");
    }

    @Test
    public void challenge_eight() throws Exception {
        SetOne.detectEcbEncryptedCipherTextFromFile("files/8.txt");
    }

    @Test
    public void hamming_distance_test() throws Exception {
        byte[] a = "this is a test".getBytes(StandardCharsets.US_ASCII);
        byte[] b = "wokka wokka!!!".getBytes(StandardCharsets.US_ASCII);
        int hd = SetOne.getHammingDistance(a, b);
        assertEquals(37, hd);
    }
}
