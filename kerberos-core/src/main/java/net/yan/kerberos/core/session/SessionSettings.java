package net.yan.kerberos.core.session;

public class SessionSettings {

    private String secureRandomAlgorithm;

    private String secureRandomProvider;

    private String messageDigestAlgorithm;

    private String messageDigestProvider;

    private SessionKeyProvider sessionKeyProvider;

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

    public SessionKeyProvider getSessionKeyProvider() {
        return sessionKeyProvider;
    }

    public void setSessionKeyProvider(SessionKeyProvider sessionKeyProvider) {
        this.sessionKeyProvider = sessionKeyProvider;
    }
}
