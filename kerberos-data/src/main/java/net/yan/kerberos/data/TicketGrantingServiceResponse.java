package net.yan.kerberos.data;

/**
 * TGS-Exchange response
 */
public class TicketGrantingServiceResponse {

    /**
     * Encrypted {@link ServerTicket}
     */
    private String serverTicket;

    /**
     * Current session key.
     */
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
