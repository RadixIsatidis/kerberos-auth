package net.yan.kerberos.data;

import java.io.Serializable;

/**
 * Class that providing client info witch using to create {@link ServerTicket}
 */
public class Authenticator implements Serializable {

    private static final long serialVersionUID = 6191995604128272772L;

    /**
     * the client username.
     */
    private String username;

    /**
     * the client address.
     */
    private String address;

    /**
     * create time.
     */
    private Long startTime;

    /**
     * life time.
     */
    private Long lifeTime;

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Authenticator)) return false;

        Authenticator that = (Authenticator) o;

        if (getUsername() != null ? !getUsername().equals(that.getUsername()) : that.getUsername() != null) return false;
        if (getAddress() != null ? !getAddress().equals(that.getAddress()) : that.getAddress() != null) return false;
        if (getStartTime() != null ? !getStartTime().equals(that.getStartTime()) : that.getStartTime() != null) return false;
        return getLifeTime() != null ? getLifeTime().equals(that.getLifeTime()) : that.getLifeTime() == null;

    }

    @Override
    public int hashCode() {
        int result = getUsername() != null ? getUsername().hashCode() : 0;
        result = 31 * result + (getAddress() != null ? getAddress().hashCode() : 0);
        result = 31 * result + (getStartTime() != null ? getStartTime().hashCode() : 0);
        result = 31 * result + (getLifeTime() != null ? getLifeTime().hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Authenticator{" +
                "username='" + username + '\'' +
                ", address='" + address + '\'' +
                ", startTime=" + startTime +
                ", lifeTime=" + lifeTime +
                '}';
    }
}
