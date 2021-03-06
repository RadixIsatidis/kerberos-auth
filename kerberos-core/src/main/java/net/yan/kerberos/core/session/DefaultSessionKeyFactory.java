package net.yan.kerberos.core.session;

import com.google.common.base.Strings;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

/**
 * A default {@code SessionKeyFactory } implement. Using {@link SecureRandom} to create a random number and
 * transform it to byte array using {@link MessageDigest}.
 */
public class DefaultSessionKeyFactory implements SessionKeyFactory {

    private SecureRandom secureRandom;

    private MessageDigest messageDigest;

    private SecureRandom getSecureRandom(SessionSettings _settings)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        DefaultSessionSettings settings = (DefaultSessionSettings) _settings;
        if (null == secureRandom) {
            if (Strings.isNullOrEmpty(settings.getSecureRandomProvider()))
                secureRandom = SecureRandom.getInstance(settings.getSecureRandomAlgorithm());
            else
                secureRandom = SecureRandom.getInstance(settings.getSecureRandomAlgorithm(), settings.getSecureRandomProvider());
        }
        return secureRandom;
    }

    private MessageDigest getMessageDigest(SessionSettings _settings)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        DefaultSessionSettings settings = (DefaultSessionSettings) _settings;
        if (null == messageDigest) {
            if (Strings.isNullOrEmpty(settings.getMessageDigestProvider()))
                messageDigest = MessageDigest.getInstance(settings.getMessageDigestAlgorithm());
            else
                messageDigest = MessageDigest.getInstance(settings.getMessageDigestAlgorithm(), settings.getMessageDigestProvider());
        }
        return messageDigest;
    }

    /**
     * {@inheritDoc}
     */
    public byte[] getSessionKey(SessionSettings settings)
            throws NoSuchProviderException, NoSuchAlgorithmException {
        SecureRandom prng = getSecureRandom(settings);
        String randomNum = Integer.toString(prng.nextInt());
        MessageDigest sha = getMessageDigest(settings);
        return sha.digest(randomNum.getBytes());
    }
}
