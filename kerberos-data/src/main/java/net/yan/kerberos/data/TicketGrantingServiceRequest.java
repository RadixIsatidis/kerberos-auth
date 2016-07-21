package net.yan.kerberos.data;

import java.io.Serializable;

public class TicketGrantingServiceRequest implements Serializable {


    private static final long serialVersionUID = 163195294338279593L;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TicketGrantingServiceRequest)) return false;

        TicketGrantingServiceRequest that = (TicketGrantingServiceRequest) o;

        if (getAuthenticatiorString() != null ? !getAuthenticatiorString().equals(that.getAuthenticatiorString()) : that.getAuthenticatiorString() != null) return false;
        if (getClientTicketGrantingTicketString() != null ? !getClientTicketGrantingTicketString().equals(that.getClientTicketGrantingTicketString()) : that.getClientTicketGrantingTicketString() != null)
            return false;
        return getServerTicketGrantingTicketString() != null ? getServerTicketGrantingTicketString().equals(that.getServerTicketGrantingTicketString()) : that.getServerTicketGrantingTicketString() == null;

    }

    @Override
    public int hashCode() {
        int result = getAuthenticatiorString() != null ? getAuthenticatiorString().hashCode() : 0;
        result = 31 * result + (getClientTicketGrantingTicketString() != null ? getClientTicketGrantingTicketString().hashCode() : 0);
        result = 31 * result + (getServerTicketGrantingTicketString() != null ? getServerTicketGrantingTicketString().hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "TicketGrantingServiceRequest{" +
                "authenticatiorString='" + authenticatiorString + '\'' +
                ", clientTicketGrantingTicketString='" + clientTicketGrantingTicketString + '\'' +
                ", serverTicketGrantingTicketString='" + serverTicketGrantingTicketString + '\'' +
                '}';
    }
}
