package net.yan.kerberos.client.tgc;

import net.yan.kerberos.data.ServerTicket;

public class TicketGrantingServiceResponseWrapper {

    /**
     * Encrypted {@link ServerTicket}
     */
    private String serverTicket;

    /**
     * Current session key
     */
    private String serverSessionKey;

    public String getServerTicket() {
        return serverTicket;
    }

    public void setServerTicket(String serverTicket) {
        this.serverTicket = serverTicket;
    }

    public String getServerSessionKey() {
        return serverSessionKey;
    }

    public void setServerSessionKey(String serverSessionKey) {
        this.serverSessionKey = serverSessionKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TicketGrantingServiceResponseWrapper)) return false;

        TicketGrantingServiceResponseWrapper wrapper = (TicketGrantingServiceResponseWrapper) o;

        if (getServerTicket() != null ? !getServerTicket().equals(wrapper.getServerTicket()) : wrapper.getServerTicket() != null) return false;
        return getServerSessionKey() != null ? getServerSessionKey().equals(wrapper.getServerSessionKey()) : wrapper.getServerSessionKey() == null;

    }

    @Override
    public int hashCode() {
        int result = getServerTicket() != null ? getServerTicket().hashCode() : 0;
        result = 31 * result + (getServerSessionKey() != null ? getServerSessionKey().hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "TicketGrantingServiceResponseWrapper{" +
                "serverTicket='" + serverTicket + '\'' +
                ", serverSessionKey='" + serverSessionKey + '\'' +
                '}';
    }
}
