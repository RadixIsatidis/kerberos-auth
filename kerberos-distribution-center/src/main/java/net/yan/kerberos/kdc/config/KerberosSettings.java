package net.yan.kerberos.kdc.config;

/**
 * Providing core settings.
 */
public interface KerberosSettings {

    /**
     * @return session life-time
     */
    Long getSessionLifeTime();

    /**
     * @return Ticket granting server address.
     */
    String getTicketGrantingServerName();

    /**
     * @return KDC master key
     */
    String getMasterKey();

}
