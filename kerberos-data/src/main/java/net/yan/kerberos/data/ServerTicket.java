package net.yan.kerberos.data;

import java.io.Serializable;

/**
 * A server ticket using to identify client identity.
 */
public class ServerTicket implements Serializable {

    private static final long serialVersionUID = -4269131580052198764L;

    /**
     * The user name witch this server ticket belong to.
     */
    private String username;

    /**
     * The server address.
     */
    private String address;

    /**
     * session key start time.
     */
    private Long startTime;

    /**
     * session key life time.
     */
    private Long lifeTime;

    /**
     * session key string.
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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ServerTicket)) return false;

        ServerTicket that = (ServerTicket) o;

        if (getUsername() != null ? !getUsername().equals(that.getUsername()) : that.getUsername() != null) return false;
        if (getAddress() != null ? !getAddress().equals(that.getAddress()) : that.getAddress() != null) return false;
        if (getStartTime() != null ? !getStartTime().equals(that.getStartTime()) : that.getStartTime() != null) return false;
        if (getLifeTime() != null ? !getLifeTime().equals(that.getLifeTime()) : that.getLifeTime() != null) return false;
        return getSessionKey() != null ? getSessionKey().equals(that.getSessionKey()) : that.getSessionKey() == null;

    }

    @Override
    public int hashCode() {
        int result = getUsername() != null ? getUsername().hashCode() : 0;
        result = 31 * result + (getAddress() != null ? getAddress().hashCode() : 0);
        result = 31 * result + (getStartTime() != null ? getStartTime().hashCode() : 0);
        result = 31 * result + (getLifeTime() != null ? getLifeTime().hashCode() : 0);
        result = 31 * result + (getSessionKey() != null ? getSessionKey().hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "ServerTicket{" +
                "username='" + username + '\'' +
                ", address='" + address + '\'' +
                ", startTime=" + startTime +
                ", lifeTime=" + lifeTime +
                ", sessionKey='" + sessionKey + '\'' +
                '}';
    }
}
