package projectone;
import java.util.Arrays;
public class AES {

    private static final byte[][] sBox = {
        {(byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5, (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76},
        {(byte)0xca, (byte)0x82, (byte)0xc9, (byte)0x7d, (byte)0xfa, (byte)0x59, (byte)0x47, (byte)0xf0, (byte)0xad, (byte)0xd4, (byte)0xa2, (byte)0xaf, (byte)0x9c, (byte)0xa4, (byte)0x72, (byte)0xc0},
        {(byte)0xb7, (byte)0xfd, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3f, (byte)0xf7, (byte)0xcc, (byte)0x34, (byte)0xa5, (byte)0xe5, (byte)0xf1, (byte)0x71, (byte)0xd8, (byte)0x31, (byte)0x15},
        {(byte)0x04, (byte)0xc7, (byte)0x23, (byte)0xc3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9a, (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xe2, (byte)0xeb, (byte)0x27, (byte)0xb2, (byte)0x75},
        {(byte)0x09, (byte)0x83, (byte)0x2c, (byte)0x1a, (byte)0x1b, (byte)0x6e, (byte)0x5a, (byte)0xa0, (byte)0x52, (byte)0x3b, (byte)0xd6, (byte)0xb3, (byte)0x29, (byte)0xe3, (byte)0x2f, (byte)0x84},
        {(byte)0x53, (byte)0xd1, (byte)0x00, (byte)0xed, (byte)0x20, (byte)0xfc, (byte)0xb1, (byte)0x5b, (byte)0x6a, (byte)0xcb, (byte)0xbe, (byte)0x39, (byte)0x4a, (byte)0x4c, (byte)0x58, (byte)0xcf},
        {(byte)0xd0, (byte)0xef, (byte)0xaa, (byte)0xfb, (byte)0x43, (byte)0x4d, (byte)0x33, (byte)0x85, (byte)0x45, (byte)0xf9, (byte)0x02, (byte)0x7f, (byte)0x50, (byte)0x3c, (byte)0x9f, (byte)0xa8},
        {(byte)0x51, (byte)0xa3, (byte)0x40, (byte)0x8f, (byte)0x92, (byte)0x9d, (byte)0x38, (byte)0xf5, (byte)0xbc, (byte)0xb6, (byte)0xda, (byte)0x21, (byte)0x10, (byte)0xff, (byte)0xf3, (byte)0xd2},
        {(byte)0xcd, (byte)0x0c, (byte)0x13, (byte)0xec, (byte)0x5f, (byte)0x97, (byte)0x44, (byte)0x17, (byte)0xc4, (byte)0xa7, (byte)0x7e, (byte)0x3d, (byte)0x64, (byte)0x5d, (byte)0x19, (byte)0x73},
        {(byte)0x60, (byte)0x81, (byte)0x4f, (byte)0xdc, (byte)0x22, (byte)0x2a, (byte)0x90, (byte)0x88, (byte)0x46, (byte)0xee, (byte)0xb8, (byte)0x14, (byte)0xde, (byte)0x5e, (byte)0x0b, (byte)0xdb},
        {(byte)0xe0, (byte)0x32, (byte)0x3a, (byte)0x0a, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5c, (byte)0xc2, (byte)0xd3, (byte)0xac, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xe4, (byte)0x79},
        {(byte)0xe7, (byte)0xc8, (byte)0x37, (byte)0x6d, (byte)0x8d, (byte)0xd5, (byte)0x4e, (byte)0xa9, (byte)0x6c, (byte)0x56, (byte)0xf4, (byte)0xea, (byte)0x65, (byte)0x7a, (byte)0xae, (byte)0x08},
        {(byte)0xba, (byte)0x78, (byte)0x25, (byte)0x2e, (byte)0x1c, (byte)0xa6, (byte)0xb4, (byte)0xc6, (byte)0xe8, (byte)0xdd, (byte)0x74, (byte)0x1f, (byte)0x4b, (byte)0xbd, (byte)0x8b, (byte)0x8a},
        {(byte)0x70, (byte)0x3e, (byte)0xb5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xf6, (byte)0x0e, (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xb9, (byte)0x86, (byte)0xc1, (byte)0x1d, (byte)0x9e},
        {(byte)0xe1, (byte)0xf8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xd9, (byte)0x8e, (byte)0x94, (byte)0x9b, (byte)0x1e, (byte)0x87, (byte)0xe9, (byte)0xce, (byte)0x55, (byte)0x28, (byte)0xdf},
        {(byte)0x8c, (byte)0xa1, (byte)0x89, (byte)0x0d, (byte)0xbf, (byte)0xe6, (byte)0x42, (byte)0x68, (byte)0x41, (byte)0x99, (byte)0x2d, (byte)0x0f, (byte)0xb0, (byte)0x54, (byte)0xbb, (byte)0x16},
    };
    
    private static final byte[][] invBox = {
        {(byte)0x52, (byte)0x09, (byte)0x6a, (byte)0xd5, (byte)0x30, (byte)0x36, (byte)0xa5, (byte)0x38, (byte)0xbf, (byte)0x40, (byte)0xa3, (byte)0x9e, (byte)0x81, (byte)0xf3, (byte)0xd7, (byte)0xfb},
        {(byte)0x7c, (byte)0xe3, (byte)0x39, (byte)0x82, (byte)0x9b, (byte)0x2f, (byte)0xff, (byte)0x87, (byte)0x34, (byte)0x8e, (byte)0x43, (byte)0x44, (byte)0xc4, (byte)0xde, (byte)0xe9, (byte)0xcb},
        {(byte)0x54, (byte)0x7b, (byte)0x94, (byte)0x32, (byte)0xa6, (byte)0xc2, (byte)0x23, (byte)0x3d, (byte)0xee, (byte)0x4c, (byte)0x95, (byte)0x0b, (byte)0x42, (byte)0xfa, (byte)0xc3, (byte)0x4e},
        {(byte)0x08, (byte)0x2e, (byte)0xa1, (byte)0x66, (byte)0x28, (byte)0xd9, (byte)0x24, (byte)0xb2, (byte)0x76, (byte)0x5b, (byte)0xa2, (byte)0x49, (byte)0x6d, (byte)0x8b, (byte)0xd1, (byte)0x25},
        {(byte)0x72, (byte)0xf8, (byte)0xf6, (byte)0x64, (byte)0x86, (byte)0x68, (byte)0x98, (byte)0x16, (byte)0xd4, (byte)0xa4, (byte)0x5c, (byte)0xcc, (byte)0x5d, (byte)0x65, (byte)0xb6, (byte)0x92},
        {(byte)0x6c, (byte)0x70, (byte)0x48, (byte)0x50, (byte)0xfd, (byte)0xed, (byte)0xb9, (byte)0xda, (byte)0x5e, (byte)0x15, (byte)0x46, (byte)0x57, (byte)0xa7, (byte)0x8d, (byte)0x9d, (byte)0x84},
        {(byte)0x90, (byte)0xd8, (byte)0xab, (byte)0x00, (byte)0x8c, (byte)0xbc, (byte)0xd3, (byte)0x0a, (byte)0xf7, (byte)0xe4, (byte)0x58, (byte)0x05, (byte)0xb8, (byte)0xb3, (byte)0x45, (byte)0x06},
        {(byte)0xd0, (byte)0x2c, (byte)0x1e, (byte)0x8f, (byte)0xca, (byte)0x3f, (byte)0x0f, (byte)0x02, (byte)0xc1, (byte)0xaf, (byte)0xbd, (byte)0x03, (byte)0x01, (byte)0x13, (byte)0x8a, (byte)0x6b},
        {(byte)0x3a, (byte)0x91, (byte)0x11, (byte)0x41, (byte)0x4f, (byte)0x67, (byte)0xdc, (byte)0xea, (byte)0x97, (byte)0xf2, (byte)0xcf, (byte)0xce, (byte)0xf0, (byte)0xb4, (byte)0xe6, (byte)0x73},
        {(byte)0x96, (byte)0xac, (byte)0x74, (byte)0x22, (byte)0xe7, (byte)0xad, (byte)0x35, (byte)0x85, (byte)0xe2, (byte)0xf9, (byte)0x37, (byte)0xe8, (byte)0x1c, (byte)0x75, (byte)0xdf, (byte)0x6e},
        {(byte)0x47, (byte)0xf1, (byte)0x1a, (byte)0x71, (byte)0x1d, (byte)0x29, (byte)0xc5, (byte)0x89, (byte)0x6f, (byte)0xb7, (byte)0x62, (byte)0x0e, (byte)0xaa, (byte)0x18, (byte)0xbe, (byte)0x1b},
        {(byte)0xfc, (byte)0x56, (byte)0x3e, (byte)0x4b, (byte)0xc6, (byte)0xd2, (byte)0x79, (byte)0x20, (byte)0x9a, (byte)0xdb, (byte)0xc0, (byte)0xfe, (byte)0x78, (byte)0xcd, (byte)0x5a, (byte)0xf4},
        {(byte)0x1f, (byte)0xdd, (byte)0xa8, (byte)0x33, (byte)0x88, (byte)0x07, (byte)0xc7, (byte)0x31, (byte)0xb1, (byte)0x12, (byte)0x10, (byte)0x59, (byte)0x27, (byte)0x80, (byte)0xec, (byte)0x5f},
        {(byte)0x60, (byte)0x51, (byte)0x7f, (byte)0xa9, (byte)0x19, (byte)0xb5, (byte)0x4a, (byte)0x0d, (byte)0x2d, (byte)0xe5, (byte)0x7a, (byte)0x9f, (byte)0x93, (byte)0xc9, (byte)0x9c, (byte)0xef},
        {(byte)0xa0, (byte)0xe0, (byte)0x3b, (byte)0x4d, (byte)0xae, (byte)0x2a, (byte)0xf5, (byte)0xb0, (byte)0xc8, (byte)0xeb, (byte)0xbb, (byte)0x3c, (byte)0x83, (byte)0x53, (byte)0x99, (byte)0x61},
        {(byte)0x17, (byte)0x2b, (byte)0x04, (byte)0x7e, (byte)0xba, (byte)0x77, (byte)0xd6, (byte)0x26, (byte)0xe1, (byte)0x69, (byte)0x14, (byte)0x63, (byte)0x55, (byte)0x21, (byte)0x0c, (byte)0x7d},
    };
        

    private static final byte[] roundConstant = {
        (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80, (byte)0x1b, (byte)0x36
    };
    
    public static void main(String [] args){
        String hexkey = "2b7e151628aed2a6abf7158809cf4f3c";
        AES aes = new AES();
        String plaintext = "6bc1bee22e409f96e93d7e117393172a";
        byte[] ciphertext = aes.encrypt(hexToBytes(plaintext), hexToBytes(hexkey));
        byte[] decrypted = aes.decrypt(ciphertext, hexToBytes(hexkey));
        System.out.println("Plaintext: " + plaintext);
        System.out.println("Ciphertext: " + bytesToHex(ciphertext));
        System.out.println("Decrypted: " + bytesToHex(decrypted));
    }

    // Constructor
    public AES() {
    }

    // helpers for converting between byte arrays and hex strings
    static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    static byte[] hexToBytes(String hexString) {
        byte [] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < 16; i++) {
            String byteStr = hexString.substring(i * 2, i * 2 + 2); //extract 2 characters at a time
            bytes[i] = (byte) Integer.parseInt(byteStr, 16); //conver to int and cast to byte
        }
        return bytes;
    }

    // encryption function and its helper functions
    byte[] encrypt(byte[] plaintext, byte[] key) {
        // Check that the input is valid
        if (plaintext.length != 16 || key.length != 16) {
            throw new IllegalArgumentException("Invalid input size");
        }
        
        byte[] expandedKey = expandKey(key); // Calculate the expanded key
        byte[] state = new byte[16];
        byte[] roundKey = Arrays.copyOfRange(expandedKey, 0, 16);
    
        // Copy the plaintext to the state
        System.arraycopy(plaintext, 0, state, 0, 16);

        // Initial round is just addRoundKey()
        addRoundKey(state, roundKey);
    
        // Perform 9 rounds of encryption: The 4 steps per round are byte substitution, row shift, column mixing, and add round key
        for (int round = 1; round <= 9; round++) {

            // Perform the byte substitution step
            for (int i = 0; i < 16; i++) {
                state[i] = sBoxSubstitution(state[i]);
            }
            
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, Arrays.copyOfRange(expandedKey, round * 16, (round + 1) * 16));
        }

        //Perform the final round of encryption: byte substitution, row shift, and add round key (no mix columns step)
        for (int i = 0; i < 16; i++) {
            state[i] = sBoxSubstitution(state[i]);
        }
        shiftRows(state);
        addRoundKey(state, Arrays.copyOfRange(expandedKey, 160, 176));

        return state;
    }

    void printState(byte[] state) {
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                System.out.print(String.format("%02x ", state[row + 4 * col]));
            }
            System.out.println();
        }
        System.out.println();
    }

    // helper functions for encryption
    byte[] expandKey(byte[] key) {
        byte[] expandedKey = new byte[176];

        // Copy the original key to the beginning of the expanded key
        System.arraycopy(key, 0, expandedKey, 0, key.length);

        // Generate the remaining round keys
        for (int i = 16; i < 176; i += 16) {
            // Copy the last 4 bytes of the previous round key in a temp array
            byte[] temp = Arrays.copyOfRange(expandedKey, i - 4, i);

            // Perform the rotation operation
            temp = rotateBytes(temp);

            // Apply the S-box substitution to each byte of temp
            for (int j = 0; j < 4; j++) {
                temp[j] = sBoxSubstitution(temp[j]);
            }

            // XOR with the round constant (i goes up by increments of 16, so (i / 16) - 1 gives the current round number)
            temp[0] ^= roundConstant[(i / 16) - 1];

            // XOR the first 4 bytes with temp
            for (int j = 0; j < 4; j++) {
                expandedKey[i + j] = (byte) (expandedKey[i + j - 16] ^ temp[j]);
            }

            // XOR the remaining 12 bytes with the byte 16 positions earlier
            for (int j = 4; j < 16; j++) {
                expandedKey[i + j] = (byte) (expandedKey[i + j - 16] ^ expandedKey[i + j - 4]);
            }
        }
        return expandedKey;
    }

    byte sBoxSubstitution(byte b) {
        // Split the byte into two nibbles
        int row = (b >> 4) & 0x0F;
        int col = b & 0x0F;
    
        // Look up the substitution value in the S-box
        return sBox[row][col];
    }

    byte[] rotateBytes(byte[] bytes) {
        // Perform a 1-byte left rotation
        byte[] rotated = new byte[4];
        rotated[0] = bytes[1];
        rotated[1] = bytes[2];
        rotated[2] = bytes[3];
        rotated[3] = bytes[0];
        return rotated;
    }

    void addRoundKey(byte[] state, byte[] roundKey) {
        for (int i = 0; i < 16; i++) {
            state[i] ^= roundKey[i];
        }
    }

    void shiftRows(byte[] state) {
        byte[] temp = new byte[16];
        temp[0] = state[0];
        temp[1] = state[5];
        temp[2] = state[10];
        temp[3] = state[15];
        temp[4] = state[4];
        temp[5] = state[9];
        temp[6] = state[14];
        temp[7] = state[3];
        temp[8] = state[8];
        temp[9] = state[13];
        temp[10] = state[2];
        temp[11] = state[7];
        temp[12] = state[12];
        temp[13] = state[1];
        temp[14] = state[6];
        temp[15] = state[11];
        System.arraycopy(temp, 0, state, 0, 16);
    }

    void mixColumns(byte[] state) {
        // Perform the column mixing step
        for (int i = 0; i < 16; i += 4) {
            // Extract the current column
            byte[] column = Arrays.copyOfRange(state, i, i + 4);
            
            // Set the column's bytes to temp values for readability
            byte a = column[0];
            byte b = column[1];
            byte c = column[2];
            byte d = column[3];

            // Perform the column mixing
            state[i] = (byte) (multiply(0x02, a) ^ multiply(0x03, b) ^ c ^ d);
            state[i + 1] = (byte) (a ^ multiply(0x02, b) ^ multiply(0x03, c) ^ d);
            state[i + 2] = (byte) (a ^ b ^ multiply(0x02, c) ^ multiply(0x03, d));
            state[i + 3] = (byte) (multiply(0x03, a) ^ b ^ c ^ multiply(0x02, d));
        }
    }

    byte multiply(int multiplier, byte b) {
        // Perform multiplication in GF(2^8) using the double and add method
        int product = 0;
        for (int i = 0; i < 8; i++) {
            //if the least significant bit of b is 1, then add the multiplier to the product
            if ((b & 1) != 0) {
                product ^= multiplier; //this is the add step
            }
            
            // Check if the high bit of the multiplier is set then shift a 1 bit to the left
            boolean highBitSet = (multiplier & 0x80) != 0;
            multiplier <<= 1; //this is the double step
    
            if (highBitSet) {
                // If the high bit was set before we shifted, modulo the multipler by the irreducible polynomial
                multiplier ^= 0x11b; // modulo with the irreducible polynomial x^8 + x^4 + x^3 + x + 1 is necessary for reversability
            }
    
            b >>= 1; //shift b 1 bit to the right so we can multiply the next bit
        }
    
        return (byte) product;
    }

    byte[] decrypt(byte[] ciphertext, byte[] key) {
        // Check that the input is valid
        if (ciphertext.length != 16 || key.length != 16) {
            throw new IllegalArgumentException("Invalid input size");
        }
        
        byte[] expandedKey = expandKey(key); // Calculate the expanded key
        byte[] state = new byte[16];
        byte[] roundKey = Arrays.copyOfRange(expandedKey, 160, 176);
    
        // Copy the ciphertext to the state
        System.arraycopy(ciphertext, 0, state, 0, 16);
    
        // Initial round is just addRoundKey()
        addRoundKey(state, roundKey);
    
        // Perform 9 rounds of decryption: The 4 steps per round are inverted row shift, 
        // inverted byte substitution, add round key and inverted mix columns
        for (int round = 9; round >= 1; round--) {
            invShiftRows(state);
            
            for (int i = 0; i < 16; i++) {
                state[i] = invSBoxSubstitution(state[i]);
            }
    
            addRoundKey(state, Arrays.copyOfRange(expandedKey, round * 16, (round + 1) * 16));
            invMixColumns(state);
        }

        // Perform the final round of decryption: inverted row shift,
        // inverted byte substitution, and add round key (no inverted mix columns step)
        invShiftRows(state); 

        for (int i = 0; i < 16; i++) {
            state[i] = invSBoxSubstitution(state[i]);
        }

        addRoundKey(state, Arrays.copyOfRange(expandedKey, 0, 16));
        return state;
    }

    // helper functions for decryption
    byte invSBoxSubstitution(byte b) {
        // Split the byte into two nibbles
        int row = (b >> 4) & 0x0F;
        int col = b & 0x0F;
    
        // Look up the substitution value in the inverted S-box
        return invBox[row][col];
    }

    void invShiftRows(byte[] state) {
        byte[] temp = new byte[16];
        temp[0] = state[0];
        temp[1] = state[13];
        temp[2] = state[10];
        temp[3] = state[7];
        temp[4] = state[4];
        temp[5] = state[1];
        temp[6] = state[14];
        temp[7] = state[11];
        temp[8] = state[8];
        temp[9] = state[5];
        temp[10] = state[2];
        temp[11] = state[15];
        temp[12] = state[12];
        temp[13] = state[9];
        temp[14] = state[6];
        temp[15] = state[3];
        System.arraycopy(temp, 0, state, 0, 16);
    }

    void invMixColumns(byte[] state) {
        // Perform the inverted column mixing step
        for (int i = 0; i < 16; i += 4) {
            // Extract the current column
            byte[] column = Arrays.copyOfRange(state, i, i + 4);
            
            // Set the column's bytes to temp values for readability
            byte a = column[0];
            byte b = column[1];
            byte c = column[2];
            byte d = column[3];

            // Perform the inverted column mixing
            state[i] = (byte) (multiply(0x0e, a) ^ multiply(0x0b, b) ^ multiply(0x0d, c) ^ multiply(0x09, d));
            state[i + 1] = (byte) (multiply(0x09, a) ^ multiply(0x0e, b) ^ multiply(0x0b, c) ^ multiply(0x0d, d));
            state[i + 2] = (byte) (multiply(0x0d, a) ^ multiply(0x09, b) ^ multiply(0x0e, c) ^ multiply(0x0b, d));
            state[i + 3] = (byte) (multiply(0x0b, a) ^ multiply(0x0d, b) ^ multiply(0x09, c) ^ multiply(0x0e, d));
        }
    }
}