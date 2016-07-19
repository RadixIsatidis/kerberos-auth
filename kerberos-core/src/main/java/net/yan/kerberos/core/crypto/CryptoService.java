package net.yan.kerberos.core.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * Providing encryption and decryption services.
 */
public class CryptoService {

    private final CryptoProvider _cryptoProvider;

    private final CryptoSettings _settings;

    public CryptoProvider getCryptoProvider() {
        return _cryptoProvider;
    }

    public CryptoSettings getSettings() {
        return _settings;
    }

    public CryptoService() {
        this(new DefaultCryptoSettings());
    }

    public CryptoService(CryptoSettings settings) {
        this(new DefaultCryptoProvider(), settings);
    }

    public CryptoService(CryptoProvider cryptoProvider) {
        this(cryptoProvider, new DefaultCryptoSettings());
    }

    public CryptoService(CryptoProvider cryptoProvider, CryptoSettings settings) {
        _cryptoProvider = cryptoProvider;
        _settings = settings;
    }

    public SecretKey generateKey(KeySpec keySpec) throws GeneralSecurityException {
        return _cryptoProvider.generateKey(_settings, keySpec);
    }

    /**
     * Read the object from Base64 string.
     *
     * @param s
     * @return
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private static Object fromString(String s) throws IOException,
            ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(data));
        Object o = ois.readObject();
        ois.close();
        return o;
    }

    /**
     * Write the object to a Base64 string.
     *
     * @param o
     * @return
     * @throws IOException
     */
    private static String toString(Serializable o) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    public <T extends Serializable> String encryptObject(T obj, String key) throws IOException, GeneralSecurityException {
        String input = toString(obj);
        return encryptString(input, _cryptoProvider.generateKey(_settings, key));
    }

    @SuppressWarnings("unchecked")
    public <T extends Serializable> T decryptObject(String input, String key) throws IOException, GeneralSecurityException, ClassNotFoundException {
        String output = decryptString(input, _cryptoProvider.generateKey(_settings, key));
        return (T) fromString(output);
    }

    public String encryptString(String input, KeySpec keySpec) throws GeneralSecurityException {
        return new String(encrypt(input.getBytes(), generateKey(keySpec)));
    }

    public String encryptString(String input, SecretKey secretKey) throws GeneralSecurityException {
        return new String(encrypt(input.getBytes(), secretKey));
    }

    public byte[] encrypt(byte[] input, SecretKey secretKey) throws GeneralSecurityException {
        Cipher cipher = _cryptoProvider.getCipher(_settings);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(input);
    }

    public String decryptString(String input, KeySpec keySpec) throws GeneralSecurityException {
        return new String(decrypt(input.getBytes(), generateKey(keySpec)));
    }

    public String decryptString(String input, SecretKey secretKey) throws GeneralSecurityException {
        return new String(decrypt(input.getBytes(), secretKey));
    }

    public byte[] decrypt(byte[] input, SecretKey secretKey) throws GeneralSecurityException {
        Cipher cipher = _cryptoProvider.getCipher(_settings);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(input);
    }
}
