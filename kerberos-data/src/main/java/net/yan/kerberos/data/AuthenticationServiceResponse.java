package net.yan.kerberos.data;

import java.io.Serializable;

public class AuthenticationServiceResponse implements Serializable {

    private String ticketGrantingTicket;

    private String sessionKey;

    private String ticketGrantingServer;

    public String getTicketGrantingTicket() {
        return ticketGrantingTicket;
    }

    public void setTicketGrantingTicket(String ticketGrantingTicket) {
        this.ticketGrantingTicket = ticketGrantingTicket;
    }

    public String getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(String sessionKey) {
        this.sessionKey = sessionKey;
    }

    public String getTicketGrantingServer() {
        return ticketGrantingServer;
    }

    public void setTicketGrantingServer(String ticketGrantingServer) {
        this.ticketGrantingServer = ticketGrantingServer;
    }
}
