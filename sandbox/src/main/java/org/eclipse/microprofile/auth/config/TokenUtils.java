package org.eclipse.microprofile.auth.config;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Key parsing related utilties
 */
public class TokenUtils {
    /**
     * Read a PEM encoded private key from the classpath
     * @param pemResName - key file resource name
     * @return PrivateKey
     * @throws Exception on decode failure
     */
    public static PrivateKey readPrivateKey(String pemResName) throws Exception {
        InputStream contentIS = TokenUtils.class.getResourceAsStream(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        PrivateKey privateKey = decodePrivateKey(new String(tmp, 0, length));
        return privateKey;
    }
    /**
     * Read a PEM encoded public key from the classpath
     * @param pemResName - key file resource name
     * @return PublicKey
     * @throws Exception on decode failure
     */
    public static PublicKey readPublicKey(String pemResName) throws Exception {
        InputStream contentIS = TokenUtils.class.getResourceAsStream(pemResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        PublicKey publicKey = decodePublicKey(new String(tmp, 0, length));
        return publicKey;
    }

    /**
     * Generate a new RSA keypair.
     * @param keySize - the size of the key
     * @return KeyPair
     * @throws NoSuchAlgorithmException on failure to load RSA key generator
     */
    public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        return keyPair;
    }

    /**
     * Decode a PEM encoded private key string to an RSA PrivateKey
     * @param pemEncoded - PEM string for private key
     * @return PrivateKey
     * @throws Exception on decode failure
     */
    public static PrivateKey decodePrivateKey(String pemEncoded) throws Exception {
        pemEncoded = removeBeginEnd(pemEncoded);
        byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(pemEncoded);

        // extract the private key

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return privKey;
    }

    /**
     * Decode a PEM encoded public key string to an RSA PublicKey
     * @param pemEncoded - PEM string for private key
     * @return PublicKey
     * @throws Exception on decode failure
     */
    public static PublicKey decodePublicKey(String pemEncoded) throws Exception {
        pemEncoded = removeBeginEnd(pemEncoded);
        byte[] encodedBytes = Base64.getDecoder().decode(pemEncoded);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private static String removeBeginEnd(String pem) {
        pem = pem.replaceAll("-----BEGIN (.*)-----", "");
        pem = pem.replaceAll("-----END (.*)----", "");
        pem = pem.replaceAll("\r\n", "");
        pem = pem.replaceAll("\n", "");
        return pem.trim();
    }

    /**
     * @return the current time in seconds since epoch
     */
    public static int currentTimeInSecs() {
        long currentTimeMS = System.currentTimeMillis();
        int currentTimeSec = (int) (currentTimeMS / 1000);
        return currentTimeSec;
    }

}
