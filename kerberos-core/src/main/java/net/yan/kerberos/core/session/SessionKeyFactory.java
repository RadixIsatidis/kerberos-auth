package net.yan.kerberos.core.session;

import java.security.GeneralSecurityException;

/**
 * Class that defines API use by {@link SessionKeyProvider}
 */
public interface SessionKeyFactory {

    /**
     * Generate a session-key
     *
     * @param settings settings.
     * @return session key string.
     * @throws GeneralSecurityException
     */
    byte[] getSessionKey(SessionSettings settings) throws GeneralSecurityException;
}
