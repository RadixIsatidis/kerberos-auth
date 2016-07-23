package net.yan.kerberos.core.secure;

import com.google.common.base.Strings;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class DefaultCipherFactory implements CipherFactory {

    private static final Log log = LogFactory.getLog(DefaultCipherFactory.class);

    /**
     * {@inheritDoc}
     */
    public Cipher getCipher(CipherSettings settings)
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
    public SecretKey generateKey(CipherSettings settings, KeySpec keySpec)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        if (log.isDebugEnabled())
            log.debug(String.format("Generate secret key using Transformation: %s, Provider: %s ", settings.getTransformation(), settings.getProvider()));
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
    public SecretKey generateKey(CipherSettings settings, String key)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, KeyException {
        if (log.isDebugEnabled())
            log.debug("String key: " + key);
        return generateKey(settings, settings.getKeySpecGenerator().generator(key));
    }
}
