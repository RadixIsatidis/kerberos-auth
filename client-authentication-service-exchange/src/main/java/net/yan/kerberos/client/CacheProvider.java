package net.yan.kerberos.client;

import net.yan.kerberos.config.ClientSettings;

/**
 * Defines the caching API.
 * <p>
 * Method {@link #get(String)} will return {@code null} when cached data expires.
 * <p>
 * The cache timeout setting must be less then (or, at least, equals) the session key
 * timeout setting {@link ClientSettings#getSessionLifeTime()}
 */
public interface CacheProvider {

    /**
     * Cache data
     *
     * @param key  the cache key.
     * @param data the data.
     * @return cached data.
     */
    String cache(String key, String data);

    /**
     * Get cached data via cache key, will return {@code null} if the cached data expires.
     *
     * @param key the cache key.
     * @return cached data, will return {@code null} if the cached data expires.
     */
    String get(String key);
}
