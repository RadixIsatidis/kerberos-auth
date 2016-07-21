package net.yan.kerberos.config;

public class KerberosSettingsBuilder {

    private Long sessionLifeTime;

    private String ticketGrantServer;

    private String masterKey;

    public Long getSessionLifeTime() {
        return sessionLifeTime;
    }

    public KerberosSettingsBuilder setSessionLifeTime(Long sessionLifeTime) {
        this.sessionLifeTime = sessionLifeTime;
        return this;
    }

    public String getTicketGrantServer() {
        return ticketGrantServer;
    }

    public KerberosSettingsBuilder setTicketGrantServer(String ticketGrantServer) {
        this.ticketGrantServer = ticketGrantServer;
        return this;
    }

    public String getMasterKey() {
        return masterKey;
    }

    public KerberosSettingsBuilder setMasterKey(String masterKey) {
        this.masterKey = masterKey;
        return this;
    }

    public KerberosSettings build() {
        final Long _sessionLifeTime = getSessionLifeTime();
        final String _ticketGrantServer = getTicketGrantServer();
        final String _masterKey = getMasterKey();
        return new KerberosSettings() {

            @Override
            public Long getSessionLifeTime() {
                return _sessionLifeTime;
            }

            @Override
            public String getTicketGrantServerName() {
                return _ticketGrantServer;
            }

            @Override
            public String getMasterKey() {
                return _masterKey;
            }
        };
    }
}
