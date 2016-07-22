package net.yan.kerberos.config;

/**
 * Builder for {@link KerberosSettings}
 *
 * @see KerberosSettings
 */
public class KerberosSettingsBuilder {

    private Long sessionLifeTime;

    private String ticketGrantServerName;

    private String masterKey;

    public Long getSessionLifeTime() {
        return sessionLifeTime;
    }

    /**
     * @see KerberosSettings#getSessionLifeTime()
     */
    public KerberosSettingsBuilder setSessionLifeTime(Long sessionLifeTime) {
        this.sessionLifeTime = sessionLifeTime;
        return this;
    }

    public String getTicketGrantServerName() {
        return ticketGrantServerName;
    }

    /**
     * @see KerberosSettings#getTicketGrantingServerName()
     */
    public KerberosSettingsBuilder setTicketGrantServerName(String ticketGrantServerName) {
        this.ticketGrantServerName = ticketGrantServerName;
        return this;
    }

    public String getMasterKey() {
        return masterKey;
    }

    /**
     * @see KerberosSettings#getMasterKey()
     */
    public KerberosSettingsBuilder setMasterKey(String masterKey) {
        this.masterKey = masterKey;
        return this;
    }

    public KerberosSettings build() {
        final Long _sessionLifeTime = getSessionLifeTime();
        final String _ticketGrantServerName = getTicketGrantServerName();
        final String _masterKey = getMasterKey();
        return new KerberosSettings() {

            @Override
            public Long getSessionLifeTime() {
                return _sessionLifeTime;
            }

            @Override
            public String getTicketGrantingServerName() {
                return _ticketGrantServerName;
            }

            @Override
            public String getMasterKey() {
                return _masterKey;
            }
        };
    }
}
