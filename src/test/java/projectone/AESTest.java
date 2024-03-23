package projectone;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

public class AESTest {
    @Test
    public void testExpandKey() throws IOException {
        // Read the correct round keys from the file
        List<String> correctKeys = Files.readAllLines(Paths.get("corrKeys.txt"));

        // Convert the correct round keys to byte arrays
        List<byte[]> correctKeyBytes = new ArrayList<>();
        for (String key : correctKeys) {
            byte[] keyBytes = new byte[16];
            for (int i = 0; i < 16; i++) {
                keyBytes[i] = (byte) Integer.parseInt(key.substring(i * 2, i * 2 + 2), 16);
            }
            correctKeyBytes.add(keyBytes);
        }

        // The initial key (example)
        byte[] initialKey = "Thats my Kung Fu".getBytes();

        // Call expandKey() to get the expanded key
        AES aes = new AES();
        byte[] expandedKey = aes.expandKey(initialKey);

        // For each round, extract the round key from the expanded key and compare it with the correct round key
        for (int round = 0; round <= 10; round++) {
            byte[] roundKey = Arrays.copyOfRange(expandedKey, round * 16, (round + 1) * 16);
            assertArrayEquals(correctKeyBytes.get(round), roundKey);
        }
    }

    @Test
    public void testInitialRound() throws Exception {
        // Read the input from zeroOutput.txt
        String content = new String(Files.readAllBytes(Paths.get("zeroOutput.txt")));
        String[] byteValues = content.split("\\s+");
        byte[] output = new byte[byteValues.length];
        for (int i = 0, len = byteValues.length; i < len; i++) {
            output[i] = (byte) Integer.parseInt(byteValues[i], 16);
        }

        // Read the input from zeroState.txt
        content = new String(Files.readAllBytes(Paths.get("zeroState.txt")));
        byteValues = content.split("\\s+");
        byte[] state = new byte[byteValues.length];
        for (int i = 0, len = byteValues.length; i < len; i++) {
            state[i] = (byte) Integer.parseInt(byteValues[i], 16);
        }
        
        // Read the input from zeroRoundKey.txt
        content = new String(Files.readAllBytes(Paths.get("zeroRoundKey.txt")));
        byteValues = content.split("\\s+");
        byte[] roundKey = new byte[byteValues.length];
        for (int i = 0, len = byteValues.length; i < len; i++) {
            roundKey[i] = (byte) Integer.parseInt(byteValues[i], 16);
        }  

        // Create an instance of AES
        AES aes = new AES();

        // Call the addRoundKey method
        aes.addRoundKey(state, roundKey);

        // Verify that the state after the method call is as expected
        assertArrayEquals(output, state);
    }

    @Test
    public void testSubBytes() throws Exception {
        // Read the input from subBytesInput.txt
        String content = new String(Files.readAllBytes(Paths.get("subBytesInput.txt")));
        String[] byteValues = content.split("\\s+");
        byte[] input = new byte[byteValues.length];
        for (int i = 0, len = byteValues.length; i < len; i++) {
            input[i] = (byte) Integer.parseInt(byteValues[i], 16);
        }

        // Read the input from subBytesOutput.txt
        content = new String(Files.readAllBytes(Paths.get("subBytesOutput.txt")));
        byteValues = content.split("\\s+");
        byte[] output = new byte[byteValues.length];
        for (int i = 0, len = byteValues.length; i < len; i++) {
            output[i] = (byte) Integer.parseInt(byteValues[i], 16);
        }

        // Create an instance of AES
        AES aes = new AES();

        // Call the subBytes method
        for (int i = 0; i < 16; i++) {
            input[i] = aes.sBoxSubstitution(input[i]);
        }

        // Verify that the state after the method call is as expected
        assertArrayEquals(output, input);
    }

    @Test
    public void testMixColumns() throws Exception {
        // Read the input from mixColumnsInput.txt
        String content = new String(Files.readAllBytes(Paths.get("mixColumnsInput.txt")));
        String[] byteValues = content.split("\\s+");
        byte[] input = new byte[byteValues.length];
        for (int i = 0, len = byteValues.length; i < len; i++) {
            input[i] = (byte) Integer.parseInt(byteValues[i], 16);
        }

        // Read the input from mixColumnsOutput.txt
        content = new String(Files.readAllBytes(Paths.get("mixColumnsOutput.txt")));
        byteValues = content.split("\\s+");
        byte[] output = new byte[byteValues.length];
        for (int i = 0, len = byteValues.length; i < len; i++) {
            output[i] = (byte) Integer.parseInt(byteValues[i], 16);
        }

        // Create an instance of AES
        AES aes = new AES();

        // Call the mixColumns method
        aes.mixColumns(input);

        // Verify that the state after the method call is as expected
        assertArrayEquals(output, input);
    }
}