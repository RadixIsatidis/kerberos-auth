package net.yan.kerberos.client;


public interface DataCache {

    void cache(String key, String ticket);

    String get(String key);
}
