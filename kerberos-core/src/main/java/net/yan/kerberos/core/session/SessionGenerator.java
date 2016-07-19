package net.yan.kerberos.core.session;


import java.security.GeneralSecurityException;

public class SessionGenerator {

    private final SessionSettings _settings;

    private static SessionGenerator sessionGenerator;

    public SessionSettings getSettings() {
        return _settings;
    }

    private SessionGenerator(SessionSettings settings) {
        _settings = settings;
    }

    public static SessionGenerator factory() {
        return factory(new DefaultSessionSettings());
    }

    public static SessionGenerator factory(SessionSettings settings) {
        if (null == sessionGenerator) {
            sessionGenerator = new SessionGenerator(settings);
        }
        return sessionGenerator;
    }

    public String generate() throws GeneralSecurityException {
        SessionKeyProvider provider = _settings.getSessionKeyProvider();
        return provider.getSessionKey(_settings);
    }
}
