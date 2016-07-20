package net.yan.kerberos.core.session;

/**
 * Default settings that using "SHA1PRNG" to init SecureRandom and "SHA-1" to MessageDigest
 */
public class DefaultSessionSettings implements SessionSettings {

    private String secureRandomAlgorithm;

    private String secureRandomProvider;

    private String messageDigestAlgorithm;

    private String messageDigestProvider;

    private SessionKeyFactory sessionKeyFactory;

    /**
     * @return the name of the RNG algorithm.
     * See the SecureRandom section in the <a href=
     * "{@docRoot}/../technotes/guides/security/StandardNames.html#SecureRandom">
     * Java Cryptography Architecture Standard Algorithm Name Documentation</a>
     * for information about standard RNG algorithm names.
     */
    public String getSecureRandomAlgorithm() {
        return secureRandomAlgorithm;
    }

    public void setSecureRandomAlgorithm(String secureRandomAlgorithm) {
        this.secureRandomAlgorithm = secureRandomAlgorithm;
    }

    /**
     * @return the name of the provider.
     */
    public String getSecureRandomProvider() {
        return secureRandomProvider;
    }

    public void setSecureRandomProvider(String secureRandomProvider) {
        this.secureRandomProvider = secureRandomProvider;
    }

    /**
     * @return the name of the algorithm requested.
     * See the MessageDigest section in the <a href=
     * "{@docRoot}/../technotes/guides/security/StandardNames.html#MessageDigest">
     * Java Cryptography Architecture Standard Algorithm Name Documentation</a>
     * for information about standard algorithm names.
     */
    public String getMessageDigestAlgorithm() {
        return messageDigestAlgorithm;
    }

    public void setMessageDigestAlgorithm(String messageDigestAlgorithm) {
        this.messageDigestAlgorithm = messageDigestAlgorithm;
    }

    /**
     * @return the name of the provider.
     */
    public String getMessageDigestProvider() {
        return messageDigestProvider;
    }

    public void setMessageDigestProvider(String messageDigestProvider) {
        this.messageDigestProvider = messageDigestProvider;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SessionKeyFactory getSessionKeyFactory() {
        return sessionKeyFactory;
    }

    public void setSessionKeyFactory(SessionKeyFactory sessionKeyFactory) {
        this.sessionKeyFactory = sessionKeyFactory;
    }

    public DefaultSessionSettings() {
        super();
        setSecureRandomAlgorithm("SHA1PRNG");
        setMessageDigestAlgorithm("SHA-1");
        setSessionKeyFactory(new DefaultSessionKeyFactory());
    }
}
