package net.yan.kerberos.core.crypto;

import java.security.KeyException;
import java.security.spec.KeySpec;

/**
 * Class that defines API used by {@link CryptoProvider}
 */
public interface KeySpecGenerator {

    /**
     * Generates a <code>SecretKey</code> object from the provided key string
     *
     * @param key the key string
     * @return the SecretKey
     * @throws KeyException if the given key is not valid
     */
    KeySpec generator(String key) throws KeyException;
}
