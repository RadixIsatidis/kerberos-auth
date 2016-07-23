package net.yan.kerberos.client.tgc;

import net.yan.kerberos.data.ServerTicket;

public class TicketGrantingServiceResponseWrapper {

    /**
     * Encrypted {@link ServerTicket}
     */
    private String serverTicket;

    /**
     * Current session key
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
