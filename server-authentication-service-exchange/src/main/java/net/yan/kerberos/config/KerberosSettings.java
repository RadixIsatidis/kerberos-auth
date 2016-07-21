package net.yan.kerberos.config;

public interface KerberosSettings {

    Long getSessionLifeTime();


    String getTicketGrantServerName();


    String getMasterKey();

}
