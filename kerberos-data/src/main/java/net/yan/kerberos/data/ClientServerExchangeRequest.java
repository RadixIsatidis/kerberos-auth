package net.yan.kerberos.data;

public class ClientServerExchangeRequest {

    private String serverName;

    private String authenticator;

    private String serverTicket;

    public String getServerName() {
        return serverName;
    }

    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    public String getAuthenticator() {
        return authenticator;
    }

    public void setAuthenticator(String authenticator) {
        this.authenticator = authenticator;
    }

    public String getServerTicket() {
        return serverTicket;
    }

    public void setServerTicket(String serverTicket) {
        this.serverTicket = serverTicket;
    }
}
