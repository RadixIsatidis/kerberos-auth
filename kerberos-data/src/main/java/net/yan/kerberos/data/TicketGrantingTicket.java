package net.yan.kerberos.data;

import java.io.Serializable;

public class TicketGrantingTicket implements Serializable {

    private String username;

    private String address;

    private String ticketGrantServer;

    private Long startTime;

    private Long lifeTime;

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
}
