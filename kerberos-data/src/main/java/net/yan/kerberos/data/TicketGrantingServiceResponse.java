package net.yan.kerberos.data;

public class TicketGrantingServiceResponse {
    private String serverTicket;

    private String serverSessionKey;

    public String getServerTicket() {
        return serverTicket;
    }

    public void setServerTicket(String serverTicket) {
        this.serverTicket = serverTicket;
    }

    public String getServerSessionKey() {
        return serverSessionKey;
    }

    public void setServerSessionKey(String serverSessionKey) {
        this.serverSessionKey = serverSessionKey;
    }
}
