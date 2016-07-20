package net.yan.kerberos.core.crypto;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Class that defines API used by {@link CryptoProvider}.
 */
public interface CryptoFactory {

    /**
     * Returns a <code>Cipher</code> object that implements the specified
     * transformation.
     *
     * @param settings the settings
     * @return a cipher that implements the requested transformation.
     * @throws NoSuchPaddingException   if <code>transformation</code>
     *                                  contains a padding scheme that is not available.
     * @throws NoSuchAlgorithmException if <code>transformation</code>
     *                                  is null, empty, in an invalid format,
     *                                  or if no Provider supports a CipherSpi implementation for the
     *                                  specified algorithm.
     * @throws NoSuchProviderException  if the specified provider is not
     *                                  registered in the security provider list.
     * @see Cipher#getInstance(String)
     * @see Cipher#getInstance(String, String)
     */
    Cipher getCipher(CryptoSettings settings)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException;

    /**
     * Generates a <code>SecretKey</code> object from the provided key
     * specification (key material) and the specified algorithm.
     *
     * @param settings the settings
     * @param keySpec  the specification (key material) of the secret key
     * @return the secret key
     * @throws NoSuchAlgorithmException if no Provider supports a
     *                                  SecretKeyFactorySpi implementation for the
     *                                  specified algorithm.
     * @throws NoSuchProviderException  if the specified provider is not
     *                                  registered in the security provider list.
     * @throws InvalidKeySpecException  if the given key specification
     *                                  is inappropriate for this secret-key factory to produce a secret key.
     * @see javax.crypto.SecretKeyFactory#getInstance(String)
     * @see javax.crypto.SecretKeyFactory#getInstance(String, String)
     * @see javax.crypto.SecretKeyFactory#generateSecret(KeySpec)
     */
    SecretKey generateKey(CryptoSettings settings, KeySpec keySpec)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException;

    /**
     * Generates a <code>SecretKey</code> object from the provided key string and the specified algorithm.
     *
     * @param settings the settings
     * @param key      the secret key string.
     * @return the secret key
     * @throws NoSuchAlgorithmException if no Provider supports a
     *                                  SecretKeyFactorySpi implementation for the
     *                                  specified algorithm.
     * @throws NoSuchProviderException  if the specified provider is not
     *                                  registered in the security provider list.
     * @throws InvalidKeySpecException  if the given key specification
     *                                  is inappropriate for this secret-key factory to produce a secret key.
     * @throws KeyException             if the given key is not valid
     * @see #generateKey(CryptoSettings, KeySpec)
     * @see KeySpecGenerator#generator(String)
     */
    SecretKey generateKey(CryptoSettings settings, String key)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, KeyException;
}
