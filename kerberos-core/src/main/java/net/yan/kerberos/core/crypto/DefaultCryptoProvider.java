package net.yan.kerberos.core.crypto;

import com.google.common.base.Strings;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;

public class DefaultCryptoProvider implements CryptoProvider {

    public Cipher getCipher(CryptoSettings settings) throws GeneralSecurityException {
        if (Strings.isNullOrEmpty(settings.getProvider())) {
            return Cipher.getInstance(settings.getTransformation());
        } else {
            return Cipher.getInstance(settings.getTransformation(), settings.getProvider());
        }
    }

    public SecretKey generateKey(CryptoSettings settings, KeySpec keySpec) throws GeneralSecurityException {
        SecretKeyFactory secretKeyFactory;
        if (Strings.isNullOrEmpty(settings.getProvider())) {
            secretKeyFactory = SecretKeyFactory.getInstance(settings.getTransformation());
        } else {
            secretKeyFactory = SecretKeyFactory.getInstance(settings.getTransformation(), settings.getProvider());
        }
        return secretKeyFactory.generateSecret(keySpec);
    }

    @Override
    public SecretKey generateKey(CryptoSettings settings, String key) throws GeneralSecurityException {
        return generateKey(settings, settings.getKeySpecGenerator().generator(key));
    }
}
