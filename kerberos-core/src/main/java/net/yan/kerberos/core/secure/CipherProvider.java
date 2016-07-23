package net.yan.kerberos.core.secure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * Providing encryption and decryption services.
 */
public class CipherProvider {

    private static final Logger log = LoggerFactory.getLogger(CipherProvider.class);

    private final CipherFactory _cipherFactory;

    private final CipherSettings _settings;

    public CipherFactory getCipherFactory() {
        return _cipherFactory;
    }

    public CipherSettings getSettings() {
        return _settings;
    }

    /**
     * Create a provider using default factory and default settings.
     */
    public CipherProvider() {
        this(new DefaultCipherSettings());
    }

    /**
     * Create a provider using a custom {@link CipherSettings} and {@link DefaultCipherFactory}
     *
     * @param settings settings
     */
    public CipherProvider(CipherSettings settings) {
        this(new DefaultCipherFactory(), settings);
    }

    /**
     * Create a provider using custom {@link CipherFactory} and {@link DefaultCipherSettings}
     *
     * @param cipherFactory a custom factory.
     */
    public CipherProvider(CipherFactory cipherFactory) {
        this(cipherFactory, new DefaultCipherSettings());
    }

    /**
     * Create a provider using custom {@link CipherFactory} and {@link CipherSettings}
     *
     * @param cipherFactory a custom factory
     * @param settings      settings
     */
    public CipherProvider(CipherFactory cipherFactory, CipherSettings settings) {
        _cipherFactory = cipherFactory;
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
        return _cipherFactory.generateKey(_settings, keySpec);
    }

    /**
     * Generates a <code>SecretKey</code> object from the provided key
     * specification (key material) and the specified algorithm.
     *
     * @param key the specification (key material) of the secret key
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
    public SecretKey generateKey(String key)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, KeyException {
        if (log.isDebugEnabled())
            log.debug("Generate secret key using key string: " + key);
        return _cipherFactory.generateKey(_settings, key);
    }

    /**
     * Read the object from Base64 string.
     *
     * @param s the Base64 string to deserialize.
     * @return an deserialized object.
     * @throws IOException            any I/O exception.
     * @throws ClassNotFoundException Class of a serialized object cannot be found.
     */
    private static Object fromString(String s)
            throws IOException, ClassNotFoundException {
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
     * @throws InvalidKeySpecException   if the given key specification
     *                                   is inappropriate for this secret-key factory to produce a secret key.
     * @throws KeyException              if the given key is not valid
     * @throws NoSuchAlgorithmException  if no Provider supports a
     *                                   SecretKeyFactorySpi implementation for the
     *                                   specified algorithm.
     * @throws NoSuchProviderException   if the specified provider is not
     *                                   registered in the security provider list.
     * @throws NoSuchPaddingException    if {@link CipherSettings#getTransformation()}
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
     * @see CipherFactory#generateKey(CipherSettings, String)
     */
    public <T extends Serializable> String encryptObject(T obj, String key)
            throws InvalidKeySpecException,
            KeyException, NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        String input;
        try {
            input = toString(obj);
        } catch (IOException e) {
            log.error(e.getMessage());
            if (log.isDebugEnabled())
                log.debug(e.getMessage(), e);
            input = "";
        }
        return encryptString(input, _cipherFactory.generateKey(_settings, key));
    }

    /**
     * Decrypt an object.
     *
     * @param input the encrypted string specific an object from {@link #encryptObject(Serializable, String)}
     * @param key   the secret key string.
     * @param <T>   type of the object.
     * @return an object.
     * @throws ClassNotFoundException    Class of a serialized object cannot be found.
     * @throws InvalidKeySpecException   if the given key specification
     *                                   is inappropriate for this secret-key factory to produce a secret key.
     * @throws KeyException              if the given key is not valid
     * @throws NoSuchAlgorithmException  if no Provider supports a
     *                                   SecretKeyFactorySpi implementation for the
     *                                   specified algorithm.
     * @throws NoSuchProviderException   if the specified provider is not
     *                                   registered in the security provider list.
     * @throws NoSuchPaddingException    if {@link CipherSettings#getTransformation()}
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
            throws ClassNotFoundException,
            InvalidKeySpecException, KeyException,
            NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        if (log.isTraceEnabled())
            log.trace(String.format("Decrypt object. input:[%s], key:[%s]", input, key));
        String output = decryptString(input, _cipherFactory.generateKey(_settings, key));
        if (log.isTraceEnabled())
            log.trace("Decrypt into string: " + output);
        try {
            return (T) fromString(output);
        } catch (IOException e) {
            log.error(e.getMessage());
            if (log.isDebugEnabled())
                log.debug(e.getMessage(), e);
            return null;
        }
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
     * @throws NoSuchPaddingException    if {@link CipherSettings#getTransformation()}
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
     * @throws NoSuchPaddingException    if {@link CipherSettings#getTransformation()}
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
     * @throws NoSuchPaddingException    if {@link CipherSettings#getTransformation()}
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
     * @see CipherFactory#getCipher(CipherSettings)
     * @see Cipher#init(int, Key)
     * @see Cipher#doFinal(byte[])
     */
    public byte[] encrypt(byte[] input, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = _cipherFactory.getCipher(_settings);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return Base64.getEncoder().encode(cipher.doFinal(input));
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
     * @throws NoSuchPaddingException    if {@link CipherSettings#getTransformation()}
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
     * @throws NoSuchPaddingException    if {@link CipherSettings#getTransformation()}
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
     * @throws NoSuchPaddingException    if {@link CipherSettings#getTransformation()}
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
     * @see CipherFactory#getCipher(CipherSettings)
     * @see Cipher#init(int, Key)
     * @see Cipher#doFinal(byte[])
     */
    public byte[] decrypt(byte[] input, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = _cipherFactory.getCipher(_settings);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        input = Base64.getDecoder().decode(input);
        return cipher.doFinal(input);
    }
}
