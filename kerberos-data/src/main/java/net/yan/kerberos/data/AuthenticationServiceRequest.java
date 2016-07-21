package net.yan.kerberos.data;

import java.io.Serializable;

/**
 * Authentication service request body <br>
 */
public class AuthenticationServiceRequest implements Serializable {


    private static final long serialVersionUID = -6251893431985394618L;
    private String username;

    private String address;

    private Long startTime;

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
        if (!(o instanceof AuthenticationServiceRequest)) return false;

        AuthenticationServiceRequest request = (AuthenticationServiceRequest) o;

        if (getUsername() != null ? !getUsername().equals(request.getUsername()) : request.getUsername() != null) return false;
        if (getAddress() != null ? !getAddress().equals(request.getAddress()) : request.getAddress() != null) return false;
        if (getStartTime() != null ? !getStartTime().equals(request.getStartTime()) : request.getStartTime() != null) return false;
        return getLifeTime() != null ? getLifeTime().equals(request.getLifeTime()) : request.getLifeTime() == null;

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
        return "AuthenticationServiceRequest{" +
                "username='" + username + '\'' +
                ", address='" + address + '\'' +
                ", startTime=" + startTime +
                ", lifeTime=" + lifeTime +
                '}';
    }
}
