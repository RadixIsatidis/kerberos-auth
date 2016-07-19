package net.yan.kerberos.config;

public class KerberosSettings {

    private Long sessionLifeTime;

    public Long getSessionLifeTime() {
        return sessionLifeTime;
    }

    public void setSessionLifeTime(Long sessionLifeTime) {
        this.sessionLifeTime = sessionLifeTime;
    }

    private String ticketGrantServer;

    public String getTicketGrantServer() {
        return ticketGrantServer;
    }

    public void setTicketGrantServer(String ticketGrantServer) {
        this.ticketGrantServer = ticketGrantServer;
    }

    private String masterKey;

    public String getMasterKey() {
        return masterKey;
    }

    public void setMasterKey(String masterKey) {
        this.masterKey = masterKey;
    }
}
