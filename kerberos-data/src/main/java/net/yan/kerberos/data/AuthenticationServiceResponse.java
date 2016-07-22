package net.yan.kerberos.data;

import java.io.Serializable;

/**
 * AS-Exchange response.
 */
public class AuthenticationServiceResponse implements Serializable {

    private static final long serialVersionUID = -812429616542585542L;

    /**
     * Encrypted {@link TicketGrantingTicket} string witch belong to current session.
     */
    private String ticketGrantingTicket;

    /**
     * Session key witch belong to current session.
     */
    private String sessionKey;

    /**
     * The ticket granting server address.
     */
    private String ticketGrantingServerName;

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

    public String getTicketGrantingServerName() {
        return ticketGrantingServerName;
    }

    public void setTicketGrantingServerName(String ticketGrantingServerName) {
        this.ticketGrantingServerName = ticketGrantingServerName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuthenticationServiceResponse)) return false;

        AuthenticationServiceResponse response = (AuthenticationServiceResponse) o;

        if (getTicketGrantingTicket() != null ? !getTicketGrantingTicket().equals(response.getTicketGrantingTicket()) : response.getTicketGrantingTicket() != null) return false;
        if (getSessionKey() != null ? !getSessionKey().equals(response.getSessionKey()) : response.getSessionKey() != null) return false;
        return getTicketGrantingServerName() != null ? getTicketGrantingServerName().equals(response.getTicketGrantingServerName()) : response.getTicketGrantingServerName() == null;

    }

    @Override
    public int hashCode() {
        int result = getTicketGrantingTicket() != null ? getTicketGrantingTicket().hashCode() : 0;
        result = 31 * result + (getSessionKey() != null ? getSessionKey().hashCode() : 0);
        result = 31 * result + (getTicketGrantingServerName() != null ? getTicketGrantingServerName().hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "AuthenticationServiceResponse{" +
                "ticketGrantingTicket='" + ticketGrantingTicket + '\'' +
                ", sessionKey='" + sessionKey + '\'' +
                ", ticketGrantingServerName='" + ticketGrantingServerName + '\'' +
                '}';
    }
}
