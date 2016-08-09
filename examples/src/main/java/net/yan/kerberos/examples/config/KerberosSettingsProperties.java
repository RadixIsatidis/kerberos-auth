package net.yan.kerberos.examples.config;

import net.yan.kerberos.kdc.config.KerberosSettings;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author yanle
 */
@ConfigurationProperties(prefix = "kerberos")
public class KerberosSettingsProperties implements KerberosSettings {

    private Long sessionLifeTime;

    private String ticketGrantingServerName;

    private String masterKey;

    public void setSessionLifeTime(Long sessionLifeTime) {
        this.sessionLifeTime = sessionLifeTime;
    }

    public void setTicketGrantingServerName(String ticketGrantingServerName) {
        this.ticketGrantingServerName = ticketGrantingServerName;
    }

    public void setMasterKey(String masterKey) {
        this.masterKey = masterKey;
    }

    @Override
    public Long getSessionLifeTime() {
        return sessionLifeTime;
    }

    @Override
    public String getTicketGrantingServerName() {
        return ticketGrantingServerName;
    }

    @Override
    public String getMasterKey() {
        return masterKey;
    }
}
