package net.yan.kerberos.data;

import java.io.Serializable;

/**
 * TGS-Exchange request.
 */
public class TicketGrantingServiceRequest implements Serializable {


    private static final long serialVersionUID = 163195294338279593L;

    /**
     * Encrypted {@link Authenticator}
     */
    private String authenticatorString;

    /**
     * Decrypted authenticator.
     */
    private Authenticator authenticator;

    /**
     * Encrypted client {@link TicketGrantingTicket}
     */
    private String clientTicketGrantingTicketString;

    /**
     * Decrypted client ticket granting ticket.
     */
    private TicketGrantingTicket clientTicketGrantingTicket;

    /**
     * Encrypted server {@link TicketGrantingTicket}
     */
    private String serverTicketGrantingTicketString;

    /**
     * Decrypted server ticket granting ticket
     */
    private TicketGrantingTicket serverTicketGrantingTicket;

    public String getAuthenticatorString() {
        return authenticatorString;
    }

    public void setAuthenticatorString(String authenticatorString) {
        this.authenticatorString = authenticatorString;
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

        if (getAuthenticatorString() != null ? !getAuthenticatorString().equals(that.getAuthenticatorString()) : that.getAuthenticatorString() != null) return false;
        if (getClientTicketGrantingTicketString() != null ? !getClientTicketGrantingTicketString().equals(that.getClientTicketGrantingTicketString()) : that.getClientTicketGrantingTicketString() != null)
            return false;
        return getServerTicketGrantingTicketString() != null ? getServerTicketGrantingTicketString().equals(that.getServerTicketGrantingTicketString()) : that.getServerTicketGrantingTicketString() == null;

    }

    @Override
    public int hashCode() {
        int result = getAuthenticatorString() != null ? getAuthenticatorString().hashCode() : 0;
        result = 31 * result + (getClientTicketGrantingTicketString() != null ? getClientTicketGrantingTicketString().hashCode() : 0);
        result = 31 * result + (getServerTicketGrantingTicketString() != null ? getServerTicketGrantingTicketString().hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "TicketGrantingServiceRequest{" +
                "authenticatorString='" + authenticatorString + '\'' +
                ", clientTicketGrantingTicketString='" + clientTicketGrantingTicketString + '\'' +
                ", serverTicketGrantingTicketString='" + serverTicketGrantingTicketString + '\'' +
                '}';
    }
}
