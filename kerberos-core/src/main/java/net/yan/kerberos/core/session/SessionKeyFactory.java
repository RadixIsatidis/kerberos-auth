package net.yan.kerberos.core.session;

import java.security.GeneralSecurityException;

/**
 * Class that defines API use by {@link SessionGenerator}
 */
public interface SessionKeyFactory {

    /**
     * Generate a session-key
     *
     * @param settings settings.
     * @return session key string.
     * @throws GeneralSecurityException
     */
    String getSessionKey(SessionSettings settings) throws GeneralSecurityException;
}
