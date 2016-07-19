package net.yan.kerberos.data;

public class TicketGrantingServiceRequest {

    private String authenticatiorString;

    private Authenticator authenticator;

    private String clientTicketGrantingTicketString;

    private TicketGrantingTicket clientTicketGrantingTicket;

    private String serverTicketGrantingTicketString;

    private TicketGrantingTicket serverTicketGrantingTicket;

    public String getAuthenticatiorString() {
        return authenticatiorString;
    }

    public void setAuthenticatiorString(String authenticatiorString) {
        this.authenticatiorString = authenticatiorString;
    }

    public Authenticator getAuthenticator() {
        return authenticator;
    }

    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    public String getClientTicketGrantingTicketString() {
        return clientTicketGrantingTicketString;
    }

    public void setClientTicketGrantingTicketString(String clientTicketGrantingTicketString) {
        this.clientTicketGrantingTicketString = clientTicketGrantingTicketString;
    }

    public TicketGrantingTicket getClientTicketGrantingTicket() {
        return clientTicketGrantingTicket;
    }

    public void setClientTicketGrantingTicket(TicketGrantingTicket clientTicketGrantingTicket) {
        this.clientTicketGrantingTicket = clientTicketGrantingTicket;
    }

    public String getServerTicketGrantingTicketString() {
        return serverTicketGrantingTicketString;
    }

    public void setServerTicketGrantingTicketString(String serverTicketGrantingTicketString) {
        this.serverTicketGrantingTicketString = serverTicketGrantingTicketString;
    }

    public TicketGrantingTicket getServerTicketGrantingTicket() {
        return serverTicketGrantingTicket;
    }

    public void setServerTicketGrantingTicket(TicketGrantingTicket serverTicketGrantingTicket) {
        this.serverTicketGrantingTicket = serverTicketGrantingTicket;
    }
}
