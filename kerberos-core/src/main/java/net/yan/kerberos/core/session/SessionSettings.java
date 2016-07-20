package net.yan.kerberos.core.session;

/**
 * The session settings.
 */
public interface SessionSettings {

    /**
     * @return a {@link SessionKeyFactory} to generate session key.
     */
    SessionKeyFactory getSessionKeyFactory();
}
