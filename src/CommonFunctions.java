import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Arrays.copyOfRange;

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

    private static byte[] getXorBytes(byte[] a, byte[] b) {
        byte[] xorBytes = new byte[a.length];
        for (int i = 0; i < xorBytes.length; i++) {
            xorBytes[i] = (byte) (a[i] ^ b[i]);
        }
        return xorBytes;
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
        byte[] xorBytes = getXorBytes(decodedHex1, decodedHex2);
        return Hex.encodeHexString(xorBytes);
    }

    public static List<String> findSingleXorCipherAndMessage(String xordMessage) throws DecoderException {
        HashMap<Character, String> cipherMessageMap = new HashMap<>();
        for (int i = 0; i < 256; i++) {
            cipherMessageMap.put((char) i, decryptRepeatingXorCipher(xordMessage, Integer.toHexString(i)));
        }

        Character bestCipher = findBestScoreCipher(cipherMessageMap);
        return Arrays.asList(String.valueOf(bestCipher), cipherMessageMap.get(bestCipher));
    }

    public static String decryptRepeatingXorCipher(String xordMessage, String cipher) throws DecoderException {
        StringBuilder sb = new StringBuilder();
        while (sb.length() <= xordMessage.length()) {
            sb.append(cipher);
        }
        String cipherExtended = sb.toString().substring(0, xordMessage.length());
        String messageHex = hexXor(xordMessage, cipherExtended);
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

    public static List<String> findEncryptedStringFromFile(String filePath) throws DecoderException, IOException {
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

        return Arrays.asList(encryptedString, bestDecryptions.get(encryptedString));
    }

    public static String encryptWithRepeatingKeyXor(String message, String cipher) {
        StringBuilder cipherExtended = new StringBuilder();
        for (int i = 0; i < message.length(); i++) {
            cipherExtended.append(cipher.charAt(i % cipher.length()));
        }

        byte[] messageBytes = message.getBytes(StandardCharsets.US_ASCII);
        byte[] cipherBytes = cipherExtended.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] encryptedBytes = getXorBytes(messageBytes, cipherBytes);
        return Hex.encodeHexString(encryptedBytes);
    }

    public static int getHammingDistance(byte[] a, byte[] b) {
        int result = 0;
        byte[] xorBytes = getXorBytes(a, b);
        for (int i = 0; i < xorBytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                if (((xorBytes[i] >> j) & 1) == 1)
                    result++;
            }
        }
        return result;
    }

    private static int getBestRepeatingKeySize(byte[] encryptedBytes) {
        int bestKeySize = 0;
        double bestHammingDistance = Double.MAX_VALUE;
        for (int i = 2; i <= 40; i++) {
            double avgHammingDistance = 0;
            for (int j = i; j < encryptedBytes.length - i; j += i) {
                byte[] c1 = Arrays.copyOfRange(encryptedBytes, j - i, j);
                byte[] c2 = Arrays.copyOfRange(encryptedBytes, j, j + i);
                avgHammingDistance += (double) getHammingDistance(c1, c2) / i;
            }
            avgHammingDistance /= ((double)encryptedBytes.length / i);
            if (avgHammingDistance < bestHammingDistance) {
                bestHammingDistance = avgHammingDistance;
                bestKeySize = i;
            }
        }
        return bestKeySize;
    }

    private static List<String> getEncodedTransposedCipherBlocks(byte[] encryptedBytes, int keySize) {
        List<List<Byte>> transposed = new ArrayList<>();
        for (int i = 0; i < keySize; i++) {
            transposed.add(new ArrayList<>());
        }
        for (int i = 0; i < encryptedBytes.length; i++) {
            transposed.get(i % keySize).add(encryptedBytes[i]);
        }

        List<String> transposedCiphers = new ArrayList<>();
        for (int i = 0; i < transposed.size(); i++) {
            byte[] bytes = new byte[transposed.get(i).size()];
            for (int j = 0; j < transposed.get(i).size(); j++) {
                bytes[j] = transposed.get(i).get(j);
            }
            transposedCiphers.add(Hex.encodeHexString(bytes));
        }
        return transposedCiphers;
    }

    public static List<String> findRepeatingXorCipherAndMessage(String encryptedMessageBase64) throws DecoderException {
        byte[] encryptedBytes = Base64.decodeBase64(encryptedMessageBase64);
        int bestKeySize = getBestRepeatingKeySize(encryptedBytes);

        List<String> transposedCiphers = getEncodedTransposedCipherBlocks(encryptedBytes, bestKeySize);
        StringBuilder sb = new StringBuilder();
        for (int j = 0; j < transposedCiphers.size(); j++) {
            sb.append(findSingleXorCipherAndMessage(transposedCiphers.get(j)).get(0));
        }
        String cipherHex = Hex.encodeHexString(sb.toString().getBytes(StandardCharsets.US_ASCII));
        String decryptedMessage = decryptRepeatingXorCipher(Hex.encodeHexString(Base64.decodeBase64(encryptedMessageBase64)), cipherHex);
        System.out.println("The message is: " + decryptedMessage);

        return Arrays.asList(sb.toString(), decryptedMessage);
    }
}
