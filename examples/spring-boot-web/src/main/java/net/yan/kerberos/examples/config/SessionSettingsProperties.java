package net.yan.kerberos.examples.config;

import net.yan.kerberos.core.session.DefaultSessionKeyFactory;
import net.yan.kerberos.core.session.DefaultSessionSettings;
import net.yan.kerberos.core.session.SessionKeyFactory;
import net.yan.kerberos.core.session.SessionSettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author yanle
 */
@ConfigurationProperties(prefix = "session")
public class SessionSettingsProperties extends DefaultSessionSettings {

    private static final Logger logger = LoggerFactory.getLogger(SessionSettingsProperties.class);

    private String secureRandomAlgorithm;

    private String secureRandomProvider;

    private String messageDigestAlgorithm;

    private String messageDigestProvider;

    private Class<? extends SessionKeyFactory> sessionKeyFactory;

    private SessionKeyFactory _sessionKeyFactory;

    public String getSecureRandomAlgorithm() {
        return secureRandomAlgorithm;
    }

    public void setSecureRandomAlgorithm(String secureRandomAlgorithm) {
        this.secureRandomAlgorithm = secureRandomAlgorithm;
    }

    public String getSecureRandomProvider() {
        return secureRandomProvider;
    }

    public void setSecureRandomProvider(String secureRandomProvider) {
        this.secureRandomProvider = secureRandomProvider;
    }

    public String getMessageDigestAlgorithm() {
        return messageDigestAlgorithm;
    }

    public void setMessageDigestAlgorithm(String messageDigestAlgorithm) {
        this.messageDigestAlgorithm = messageDigestAlgorithm;
    }

    public String getMessageDigestProvider() {
        return messageDigestProvider;
    }

    public void setMessageDigestProvider(String messageDigestProvider) {
        this.messageDigestProvider = messageDigestProvider;
    }

    public void setSessionKeyFactory(Class<? extends SessionKeyFactory> sessionKeyFactory) {
        this.sessionKeyFactory = sessionKeyFactory;
    }

    @Override
    public SessionKeyFactory getSessionKeyFactory() {
        if (null == sessionKeyFactory) {
            sessionKeyFactory = DefaultSessionKeyFactory.class;
        }
        if (null == _sessionKeyFactory) {
            try {
                _sessionKeyFactory = sessionKeyFactory.newInstance();
            } catch (InstantiationException | IllegalAccessException e) {
                logger.error(e.getMessage());
                _sessionKeyFactory = new DefaultSessionKeyFactory();
            }
        }
        return _sessionKeyFactory;
    }
}
