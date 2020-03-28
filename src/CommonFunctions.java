import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CommonFunctions {
    private static final Map<Character, Double> CHAR_FREQUENCIES = initializeCharFrequencies();

    private static Map<Character, Double> initializeCharFrequencies() {
        Map<Character, Double> map = new HashMap<>();
        map.put('a', 0.08167);
        map.put('b', 0.01492);
        map.put('c', 0.02202);
        map.put('d', 0.04253);
        map.put('e', 0.12702);
        map.put('f', 0.02228);
        map.put('g', 0.02015);
        map.put('h', 0.06094);
        map.put('i', 0.06966);
        map.put('j', 0.00153);
        map.put('k', 0.01292);
        map.put('l', 0.04025);
        map.put('m', 0.02406);
        map.put('n', 0.06749);
        map.put('o', 0.07507);
        map.put('p', 0.01929);
        map.put('q', 0.00095);
        map.put('r', 0.05987);
        map.put('s', 0.06327);
        map.put('t', 0.09356);
        map.put('u', 0.02758);
        map.put('v', 0.00978);
        map.put('w', 0.02560);
        map.put('x', 0.00150);
        map.put('y', 0.01994);
        map.put('z', 0.00077);
        map.put(' ', 0.13000);
        return Collections.unmodifiableMap(map);
    }

    public static String hexToBase64(String hexString) throws DecoderException {
        byte[] decodedHex = Hex.decodeHex(hexString);
        return Base64.encodeBase64String(decodedHex);
    }

    public static String hexXor(String buffer1, String buffer2) throws DecoderException, IllegalArgumentException {
        if (buffer1.length() != buffer2.length())
            throw new IllegalArgumentException("Buffers must be of equal size.");
        byte[] decodedHex1 = Hex.decodeHex(buffer1);
        byte[] decodedHex2 = Hex.decodeHex(buffer2);
        byte[] xorBytes = new byte[decodedHex1.length];
        for (int i = 0; i < xorBytes.length; i++) {
            xorBytes[i] = (byte) (decodedHex1[i] ^ decodedHex2[i]);
        }
        return Hex.encodeHexString(xorBytes);
    }

    public static List<String> findSingleXorCipherAndMessage(String xordMessage) throws DecoderException {
        HashMap<Character, String> cipherMessageMap = new HashMap<>();
        for (int i = 65; i <= 90; i++) {
            System.out.println("Cipher: " + (char) i + " +: " + decryptSingleXorCipher(xordMessage, Integer.toHexString(i)));
            cipherMessageMap.put((char) i, decryptSingleXorCipher(xordMessage, Integer.toHexString(i)));
        }
        for (int i = 97; i <= 122; i++) {
            System.out.println("Cipher: " + (char) i + " +: " + decryptSingleXorCipher(xordMessage, Integer.toHexString(i)));
            cipherMessageMap.put((char) i, decryptSingleXorCipher(xordMessage, Integer.toHexString(i)));
        }
        Character bestCipher = findBestScoreCipher(cipherMessageMap);
        System.out.println("Found single character cipher: " + bestCipher + " with message: " + cipherMessageMap.get(bestCipher));
        return Arrays.asList(String.valueOf(bestCipher), cipherMessageMap.get(bestCipher));
    }

    public static String decryptSingleXorCipher(String xordMessage, String cipher) throws DecoderException {
        StringBuilder cipherExtended = new StringBuilder();
        while (cipherExtended.length() != xordMessage.length()) {
            cipherExtended.append(cipher);
        }
        String messageHex = hexXor(xordMessage, cipherExtended.toString());
        // return decrypted message
        return new String(Hex.decodeHex(messageHex));
    }

    public static Character findBestScoreCipher(HashMap<Character, String> cipherMessageMap) {
        Character bestKey = null;
        double bestScore = 0;
        for (Map.Entry<Character, String> entry : cipherMessageMap.entrySet()) {
            double score = scoreDecryptedMessage(entry.getValue());
            if (score > bestScore) {
                bestKey = entry.getKey();
                bestScore = score;
            }
        }
        return bestKey;
    }

    private static double scoreDecryptedMessage(String decryptedMessage) {
        String lower = decryptedMessage.toLowerCase();
        double score = 0;
        for (int i = 0; i < lower.length(); i++) {
            char c = lower.charAt(i);
            score += CHAR_FREQUENCIES.containsKey(c) ? CHAR_FREQUENCIES.get(c) : 0;
        }
        return score;
    }

    public static String findEncryptedStringFromFile(String filePath) throws DecoderException, IOException {
        String file = new String(Files.readAllBytes(Paths.get(filePath)));
        List<String> list = Arrays.asList(file.split("\n"));
        HashMap<String, String> bestDecryptions = new HashMap<>();
        for (int i = 0; i < list.size(); i++) {
            bestDecryptions.put(list.get(i), findSingleXorCipherAndMessage(list.get(i)).get(1));
        }

        String encryptedString = null;
        double bestScore = 0;
        for (Map.Entry<String, String> entry : bestDecryptions.entrySet()) {
            double score = scoreDecryptedMessage(entry.getValue());
            if (score > bestScore) {
                encryptedString = entry.getKey();
                bestScore = score;
            }
        }

        System.out.println("The encrypted string is: " + encryptedString + ". The message is: " + bestDecryptions.get(encryptedString));
        return encryptedString;
    }

    public static void main(String[] args) throws DecoderException, IOException {
        System.out.println(hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"));
        System.out.println(hexXor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"));
        System.out.println(findSingleXorCipherAndMessage("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"));

        findEncryptedStringFromFile("files/4.txt");
    }
}
