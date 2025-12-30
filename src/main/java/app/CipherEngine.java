package app;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public final class CipherEngine {
    private static final byte[] SALT = "token-crypt:v1:fixed-salt".getBytes(StandardCharsets.UTF_8);
    private static final int ITERATIONS = 300_000;   // raise later if you want
    private static final int KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;          // common for GCM

    private static final SecureRandom RNG = new SecureRandom();

    private CipherEngine() {}

    private static SecretKeySpec keyFromToken(String token) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(token.toCharArray(), SALT, ITERATIONS, KEY_BITS);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // PBKDF2 SHA-256 [web:324]
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static String encrypt(String token, String plaintext) throws Exception {
        SecretKeySpec key = keyFromToken(token);

        byte[] iv = new byte[IV_BYTES];
        RNG.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv)); // GCMParameterSpec usage [web:325]

        byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // output = base64( iv || ciphertext )
        ByteBuffer bb = ByteBuffer.allocate(iv.length + ct.length);
        bb.put(iv);
        bb.put(ct);
        return Base64.getEncoder().encodeToString(bb.array());
    }

    public static String decrypt(String token, String tokenText) throws Exception {
        SecretKeySpec key = keyFromToken(token);

        byte[] all = Base64.getDecoder().decode(tokenText.trim());
        if (all.length < IV_BYTES + 1) throw new IllegalArgumentException("Ciphertext too short");

        byte[] iv = new byte[IV_BYTES];
        byte[] ct = new byte[all.length - IV_BYTES];
        System.arraycopy(all, 0, iv, 0, IV_BYTES);
        System.arraycopy(all, IV_BYTES, ct, 0, ct.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv)); // GCMParameterSpec usage [web:325]

        byte[] pt = cipher.doFinal(ct);
        return new String(pt, StandardCharsets.UTF_8);
    }
}
// If you are reading this, why are you snooping around? There *is* no malware, trust ;)