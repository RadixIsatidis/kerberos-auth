package net.yan.kerberos.core.crypto;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * Providing encryption and decryption services.
 */
public class CryptoProvider {

    private final CryptoFactory _cryptoFactory;

    private final CryptoSettings _settings;

    public CryptoFactory getCryptoProvider() {
        return _cryptoFactory;
    }

    public CryptoSettings getSettings() {
        return _settings;
    }

    /**
     * Create a provider using default factory and default settings.
     */
    public CryptoProvider() {
        this(new DefaultCryptoSettings());
    }

    /**
     * Create a provider using a custom {@link CryptoSettings} and {@link DefaultCryptoFactory}
     *
     * @param settings settings
     */
    public CryptoProvider(CryptoSettings settings) {
        this(new DefaultCryptoFactory(), settings);
    }

    /**
     * Create a provider using custom {@link CryptoFactory} and {@link DefaultCryptoSettings}
     *
     * @param cryptoFactory a custom factory.
     */
    public CryptoProvider(CryptoFactory cryptoFactory) {
        this(cryptoFactory, new DefaultCryptoSettings());
    }

    /**
     * Create a provider using custom {@link CryptoFactory} and {@link CryptoSettings}
     *
     * @param cryptoFactory a custom factory
     * @param settings      settings
     */
    public CryptoProvider(CryptoFactory cryptoFactory, CryptoSettings settings) {
        _cryptoFactory = cryptoFactory;
        _settings = settings;
    }

    /**
     * Generates a <code>SecretKey</code> object from the provided key
     * specification (key material) and the specified algorithm.
     *
     * @param keySpec the specification (key material) of the secret key
     * @return the secret key string
     * @throws NoSuchAlgorithmException if no Provider supports a
     *                                  SecretKeyFactorySpi implementation for the
     *                                  specified algorithm.
     * @throws NoSuchProviderException  if the specified provider is not
     *                                  registered in the security provider list.
     * @throws InvalidKeySpecException  if the given key specification
     *                                  is inappropriate for this secret-key factory to produce a secret key.
     */
    public SecretKey generateKey(KeySpec keySpec)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        return _cryptoFactory.generateKey(_settings, keySpec);
    }

    /**
     * Generates a <code>SecretKey</code> object from the provided key
     * specification (key material) and the specified algorithm.
     *
     * @param keySpec the specification (key material) of the secret key
     * @return the secret key
     * @throws NoSuchAlgorithmException if no Provider supports a
     *                                  SecretKeyFactorySpi implementation for the
     *                                  specified algorithm.
     * @throws NoSuchProviderException  if the specified provider is not
     *                                  registered in the security provider list.
     * @throws InvalidKeySpecException  if the given key specification
     *                                  is inappropriate for this secret-key factory to produce a secret key.
     * @throws KeyException             if the given key is not valid
     */
    public SecretKey generateKey(String keySpec)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, KeyException {
        return _cryptoFactory.generateKey(_settings, keySpec);
    }

    /**
     * Read the object from Base64 string.
     *
     * @param s the Base64 string to deserialize.
     * @return an deserialized object.
     * @throws IOException            any I/O exception.
     * @throws ClassNotFoundException Class of a serialized object cannot be found.
     */
    private static Object fromString(String s) throws IOException,
            ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object o = ois.readObject();
        ois.close();
        return o;
    }

    /**
     * Write the object to a Base64 string.
     *
     * @param o the object to serialize.
     * @return Base64 string.
     * @throws IOException any I/O exception.
     */
    private static String toString(Serializable o) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    /**
     * Encrypt an object.
     *
     * @param obj the object to encrypt.
     * @param key the secret key string.
     * @param <T> type of the object.
     * @return encrypted string.
     * @throws IOException               any I/O error.
     * @throws InvalidKeySpecException   if the given key specification
     *                                   is inappropriate for this secret-key factory to produce a secret key.
     * @throws KeyException              if the given key is not valid
     * @throws NoSuchAlgorithmException  if no Provider supports a
     *                                   SecretKeyFactorySpi implementation for the
     *                                   specified algorithm.
     * @throws NoSuchProviderException   if the specified provider is not
     *                                   registered in the security provider list.
     * @throws NoSuchPaddingException    if {@link CryptoSettings#getTransformation()}
     *                                   contains a padding scheme that is not available.
     * @throws BadPaddingException       if this cipher is in decryption mode,
     *                                   and (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     *                                   no padding has been requested (only in encryption mode), and the total
     *                                   input length of the data processed by this cipher is not a multiple of
     *                                   block size; or if this encryption algorithm is unable to
     *                                   process the input data provided.
     * @see #toString(Serializable)
     * @see #encryptString(String, KeySpec)
     * @see CryptoFactory#generateKey(CryptoSettings, String)
     */
    public <T extends Serializable> String encryptObject(T obj, String key)
            throws IOException, InvalidKeySpecException,
            KeyException, NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        String input = toString(obj);
        return encryptString(input, _cryptoFactory.generateKey(_settings, key));
    }

    /**
     * Decrypt an object.
     *
     * @param input the encrypted string specific an object from {@link #encryptObject(Serializable, String)}
     * @param key   the secret key string.
     * @param <T>   type of the object.
     * @return an object.
     * @throws IOException               any I/O exception.
     * @throws ClassNotFoundException    Class of a serialized object cannot be found.
     * @throws InvalidKeySpecException   if the given key specification
     *                                   is inappropriate for this secret-key factory to produce a secret key.
     * @throws KeyException              if the given key is not valid
     * @throws NoSuchAlgorithmException  if no Provider supports a
     *                                   SecretKeyFactorySpi implementation for the
     *                                   specified algorithm.
     * @throws NoSuchProviderException   if the specified provider is not
     *                                   registered in the security provider list.
     * @throws NoSuchPaddingException    if {@link CryptoSettings#getTransformation()}
     *                                   contains a padding scheme that is not available.
     * @throws BadPaddingException       if this cipher is in decryption mode,
     *                                   and (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     *                                   no padding has been requested (only in encryption mode), and the total
     *                                   input length of the data processed by this cipher is not a multiple of
     *                                   block size; or if this encryption algorithm is unable to
     *                                   process the input data provided.
     */
    @SuppressWarnings("unchecked")
    public <T extends Serializable> T decryptObject(String input, String key)
            throws IOException, ClassNotFoundException,
            InvalidKeySpecException, KeyException,
            NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        String output = decryptString(input, _cryptoFactory.generateKey(_settings, key));
        return (T) fromString(output);
    }

    /**
     * Encryption.
     *
     * @param input   the input string
     * @param keySpec the secret key
     * @return a result string.
     * @throws NoSuchAlgorithmException  if no Provider supports a
     *                                   SecretKeyFactorySpi implementation for the
     *                                   specified algorithm.
     * @throws NoSuchProviderException   if the specified provider is not
     *                                   registered in the security provider list.
     * @throws InvalidKeySpecException   if the given key specification
     *                                   is inappropriate for this secret-key factory to produce a secret key.
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     *                                   no padding has been requested (only in encryption mode), and the total
     *                                   input length of the data processed by this cipher is not a multiple of
     *                                   block size; or if this encryption algorithm is unable to
     *                                   process the input data provided.
     * @throws InvalidKeyException       if the given key specification
     *                                   is inappropriate for this secret-key factory to produce a secret key.
     * @throws BadPaddingException       if this cipher is in decryption mode,
     *                                   and (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     * @throws NoSuchPaddingException    if {@link CryptoSettings#getTransformation()}
     *                                   contains a padding scheme that is not available.
     */
    public String encryptString(String input, KeySpec keySpec)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        return new String(encrypt(input.getBytes(), generateKey(keySpec)));
    }

    /**
     * Encryption.
     *
     * @param input     the input string
     * @param secretKey the secret key
     * @return a result string.
     * @throws NoSuchPaddingException    if {@link CryptoSettings#getTransformation()}
     *                                   contains a padding scheme that is not available.
     * @throws NoSuchAlgorithmException  if no Provider supports a
     *                                   SecretKeyFactorySpi implementation for the
     *                                   specified algorithm.
     * @throws NoSuchProviderException   if the specified provider is not
     *                                   registered in the security provider list.
     * @throws InvalidKeyException       if the given key specification
     *                                   is inappropriate for this secret-key factory to produce a secret key.
     * @throws BadPaddingException       if this cipher is in decryption mode,
     *                                   and (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     *                                   no padding has been requested (only in encryption mode), and the total
     *                                   input length of the data processed by this cipher is not a multiple of
     *                                   block size; or if this encryption algorithm is unable to
     *                                   process the input data provided.
     * @see #encrypt(byte[], SecretKey)
     */
    public String encryptString(String input, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        return new String(encrypt(input.getBytes(), secretKey));
    }

    /**
     * Encryption.
     *
     * @param input     the input buffer.
     * @param secretKey the secret key
     * @return the new buffer with the Base64 decoded result.
     * @throws NoSuchPaddingException    if {@link CryptoSettings#getTransformation()}
     *                                   contains a padding scheme that is not available.
     * @throws NoSuchAlgorithmException  if no Provider supports a
     *                                   SecretKeyFactorySpi implementation for the
     *                                   specified algorithm.
     * @throws NoSuchProviderException   if the specified provider is not
     *                                   registered in the security provider list.
     * @throws InvalidKeyException       if the given key specification
     *                                   is inappropriate for this secret-key factory to produce a secret key.
     * @throws BadPaddingException       if this cipher is in decryption mode,
     *                                   and (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     *                                   no padding has been requested (only in encryption mode), and the total
     *                                   input length of the data processed by this cipher is not a multiple of
     *                                   block size; or if this encryption algorithm is unable to
     *                                   process the input data provided.
     * @see CryptoFactory#getCipher(CryptoSettings)
     * @see Cipher#init(int, Key)
     * @see Cipher#doFinal(byte[])
     */
    public byte[] encrypt(byte[] input, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = _cryptoFactory.getCipher(_settings);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(Base64.getDecoder().decode(input));
    }

    /**
     * Decryption
     *
     * @param input   the input string
     * @param keySpec the specification (key material) of the secret key
     * @return a result string.
     * @throws NoSuchAlgorithmException  if no Provider supports a
     *                                   SecretKeyFactorySpi implementation for the
     *                                   specified algorithm.
     * @throws NoSuchProviderException   if the specified provider is not
     *                                   registered in the security provider list.
     * @throws InvalidKeySpecException   if the given key specification
     *                                   is inappropriate for this secret-key factory to produce a secret key.
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     *                                   no padding has been requested (only in encryption mode), and the total
     *                                   input length of the data processed by this cipher is not a multiple of
     *                                   block size; or if this encryption algorithm is unable to
     *                                   process the input data provided.
     * @throws InvalidKeyException       if the given key specification
     *                                   is inappropriate for this secret-key factory to produce a secret key.
     * @throws BadPaddingException       if this cipher is in decryption mode,
     *                                   and (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     * @throws NoSuchPaddingException    if {@link CryptoSettings#getTransformation()}
     *                                   contains a padding scheme that is not available.
     * @see #generateKey(KeySpec)
     * @see #decrypt(byte[], SecretKey)
     */
    public String decryptString(String input, KeySpec keySpec)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        return new String(decrypt(input.getBytes(), generateKey(keySpec)));
    }

    /**
     * Decryption
     *
     * @param input     the input string
     * @param secretKey the secret key
     * @return a result string.
     * @throws NoSuchPaddingException    if {@link CryptoSettings#getTransformation()}
     *                                   contains a padding scheme that is not available.
     * @throws NoSuchAlgorithmException  if no Provider supports a
     *                                   SecretKeyFactorySpi implementation for the
     *                                   specified algorithm.
     * @throws NoSuchProviderException   if the specified provider is not
     *                                   registered in the security provider list.
     * @throws InvalidKeyException       if the given key specification
     *                                   is inappropriate for this secret-key factory to produce a secret key.
     * @throws BadPaddingException       if this cipher is in decryption mode,
     *                                   and (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     *                                   no padding has been requested (only in encryption mode), and the total
     *                                   input length of the data processed by this cipher is not a multiple of
     *                                   block size; or if this encryption algorithm is unable to
     *                                   process the input data provided.
     * @see #decrypt(byte[], SecretKey)
     */
    public String decryptString(String input, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        return new String(decrypt(input.getBytes(), secretKey));
    }

    /**
     * Decryption.
     *
     * @param input     the input buffer witch return buy calling {@link #encrypt(byte[], SecretKey)}
     * @param secretKey the secret key
     * @return the new buffer with the Base64 encoded result .
     * @throws NoSuchPaddingException    if {@link CryptoSettings#getTransformation()}
     *                                   contains a padding scheme that is not available.
     * @throws NoSuchAlgorithmException  if no Provider supports a
     *                                   SecretKeyFactorySpi implementation for the
     *                                   specified algorithm.
     * @throws NoSuchProviderException   if the specified provider is not
     *                                   registered in the security provider list.
     * @throws InvalidKeyException       if the given key specification
     *                                   is inappropriate for this secret-key factory to produce a secret key.
     * @throws BadPaddingException       if this cipher is in decryption mode,
     *                                   and (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     *                                   no padding has been requested (only in encryption mode), and the total
     *                                   input length of the data processed by this cipher is not a multiple of
     *                                   block size; or if this encryption algorithm is unable to
     *                                   process the input data provided.
     * @see CryptoFactory#getCipher(CryptoSettings)
     * @see Cipher#init(int, Key)
     * @see Cipher#doFinal(byte[])
     */
    public byte[] decrypt(byte[] input, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = _cryptoFactory.getCipher(_settings);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return Base64.getEncoder().encode(cipher.doFinal(input));
    }
}
