package net.yan.kerberos.data;

import java.io.Serializable;

/**
 * TGT
 */
public class TicketGrantingTicket implements Serializable {

    private static final long serialVersionUID = -4560268207092674442L;

    /**
     * The ticket holder username.
     */
    private String username;

    /**
     * The ticket holder address
     */
    private String address;

    /**
     * The ticket granting server address.
     */
    private String ticketGrantServer;

    /**
     * Create time.
     */
    private Long startTime;

    /**
     * Life time.
     */
    private Long lifeTime;

    /**
     * Session key witch belong to current session.
     */
    private String sessionKey;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getTicketGrantServer() {
        return ticketGrantServer;
    }

    public void setTicketGrantServer(String ticketGrantServer) {
        this.ticketGrantServer = ticketGrantServer;
    }

    public Long getStartTime() {
        return startTime;
    }

    public void setStartTime(Long startTime) {
        this.startTime = startTime;
    }

    public Long getLifeTime() {
        return lifeTime;
    }

    public void setLifeTime(Long lifeTime) {
        this.lifeTime = lifeTime;
    }

    public String getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(String sessionKey) {
        this.sessionKey = sessionKey;
    }

    @Override
    public String toString() {
        return "TicketGrantingTicket{" +
                ", username='" + username + '\'' +
                ", address='" + address + '\'' +
                ", ticketGrantServer='" + ticketGrantServer + '\'' +
                ", startTime=" + startTime +
                ", lifeTime=" + lifeTime +
                ", sessionKey='" + sessionKey + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TicketGrantingTicket)) return false;

        TicketGrantingTicket that = (TicketGrantingTicket) o;

        if (getUsername() != null ? !getUsername().equals(that.getUsername()) : that.getUsername() != null) return false;
        if (getAddress() != null ? !getAddress().equals(that.getAddress()) : that.getAddress() != null) return false;
        if (getTicketGrantServer() != null ? !getTicketGrantServer().equals(that.getTicketGrantServer()) : that.getTicketGrantServer() != null) return false;
        if (getStartTime() != null ? !getStartTime().equals(that.getStartTime()) : that.getStartTime() != null) return false;
        if (getLifeTime() != null ? !getLifeTime().equals(that.getLifeTime()) : that.getLifeTime() != null) return false;
        return getSessionKey() != null ? getSessionKey().equals(that.getSessionKey()) : that.getSessionKey() == null;

    }

    @Override
    public int hashCode() {
        int result = getUsername() != null ? getUsername().hashCode() : 0;
        result = 31 * result + (getAddress() != null ? getAddress().hashCode() : 0);
        result = 31 * result + (getTicketGrantServer() != null ? getTicketGrantServer().hashCode() : 0);
        result = 31 * result + (getStartTime() != null ? getStartTime().hashCode() : 0);
        result = 31 * result + (getLifeTime() != null ? getLifeTime().hashCode() : 0);
        result = 31 * result + (getSessionKey() != null ? getSessionKey().hashCode() : 0);
        return result;
    }
}
