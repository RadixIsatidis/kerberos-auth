package net.yan.kerberos.core.crypto;

import com.google.common.base.Strings;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class DefaultCryptoFactory implements CryptoFactory {

    /**
     * {@inheritDoc}
     */
    @Override
    public Cipher getCipher(CryptoSettings settings)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        if (Strings.isNullOrEmpty(settings.getProvider())) {
            return Cipher.getInstance(settings.getTransformation());
        } else {
            return Cipher.getInstance(settings.getTransformation(), settings.getProvider());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SecretKey generateKey(CryptoSettings settings, KeySpec keySpec)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        SecretKeyFactory secretKeyFactory;
        if (Strings.isNullOrEmpty(settings.getProvider())) {
            secretKeyFactory = SecretKeyFactory.getInstance(settings.getTransformation());
        } else {
            secretKeyFactory = SecretKeyFactory.getInstance(settings.getTransformation(), settings.getProvider());
        }
        return secretKeyFactory.generateSecret(keySpec);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SecretKey generateKey(CryptoSettings settings, String key)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, KeyException {
        return generateKey(settings, settings.getKeySpecGenerator().generator(key));
    }
}
