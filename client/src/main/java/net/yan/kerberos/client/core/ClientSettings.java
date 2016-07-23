package net.yan.kerberos.client.core;


public interface ClientSettings {

    Long getSessionLifeTime();

    String getMasterKey();

    int getRetryTimes();

    String getLocalName();
}
