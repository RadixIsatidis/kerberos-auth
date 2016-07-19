package net.yan.kerberos.core.session;

import com.google.common.base.Strings;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class DefaultSessionKeyProvider implements SessionKeyProvider {

    private SecureRandom secureRandom;

    private MessageDigest messageDigest;

    public SecureRandom getSecureRandom(SessionSettings settings) throws GeneralSecurityException {
        if (null == secureRandom) {
            if (Strings.isNullOrEmpty(settings.getSecureRandomProvider()))
                secureRandom = SecureRandom.getInstance(settings.getSecureRandomAlgorithm());
            else
                secureRandom = SecureRandom.getInstance(settings.getSecureRandomAlgorithm(), settings.getSecureRandomProvider());
        }
        return secureRandom;
    }

    public MessageDigest getMessageDigest(SessionSettings settings) throws GeneralSecurityException {
        if (null == messageDigest) {
            if (Strings.isNullOrEmpty(settings.getMessageDigestProvider()))
                messageDigest = MessageDigest.getInstance(settings.getMessageDigestAlgorithm());
            else
                messageDigest = MessageDigest.getInstance(settings.getMessageDigestAlgorithm(), settings.getMessageDigestProvider());
        }
        return messageDigest;
    }

    @Override
    public String getSessionKey(SessionSettings settings) throws GeneralSecurityException {
        SecureRandom prng = getSecureRandom(settings);
        String randomNum = Integer.toString(prng.nextInt());
        MessageDigest sha = getMessageDigest(settings);
        byte[] result = sha.digest(randomNum.getBytes());
        return new String(result);
    }
}
