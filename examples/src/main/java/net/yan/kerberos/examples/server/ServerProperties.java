package net.yan.kerberos.examples.server;

import net.yan.kerberos.client.core.ClientSettings;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author yanle
 */
@ConfigurationProperties(prefix = "kerberos.server")
public class ServerProperties implements ClientSettings {

    private String authenticationServerName;

    private String localhost;

    public String getAuthenticationServerName() {
        return authenticationServerName;
    }

    public void setAuthenticationServerName(String authenticationServerName) {
        this.authenticationServerName = authenticationServerName;
    }

    public String getLocalhost() {
        return localhost;
    }

    public void setLocalhost(String localhost) {
        this.localhost = localhost;
    }

    private Long sessionLifeTime;

    private String masterKey;

    private Integer retryTimes;

    private String localName;

    @Override
    public Long getSessionLifeTime() {
        return sessionLifeTime;
    }

    @Override
    public String getMasterKey() {
        return masterKey;
    }

    @Override
    public int getRetryTimes() {
        return retryTimes;
    }

    @Override
    public String getLocalName() {
        return localName;
    }

    public void setSessionLifeTime(Long sessionLifeTime) {
        this.sessionLifeTime = sessionLifeTime;
    }

    public void setMasterKey(String masterKey) {
        this.masterKey = masterKey;
    }

    public void setRetryTimes(Integer retryTimes) {
        this.retryTimes = retryTimes;
    }

    public void setLocalName(String localName) {
        this.localName = localName;
    }
}
