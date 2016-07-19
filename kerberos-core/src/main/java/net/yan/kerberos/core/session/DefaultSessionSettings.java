package net.yan.kerberos.core.session;

public class DefaultSessionSettings extends SessionSettings {

    public DefaultSessionSettings() {
        super();
        setSecureRandomAlgorithm("SHA1PRNG");
        setMessageDigestAlgorithm("SHA-1");
        setSessionKeyProvider(new DefaultSessionKeyProvider());
    }
}
