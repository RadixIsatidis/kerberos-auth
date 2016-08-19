package net.yan.kerberos.client;

import net.yan.kerberos.core.KerberosException;
import rx.Observable;

/**
 * @author yanle
 */
public interface ClientHelper {
    /**
     * Get server session key.
     *
     * @param serverName the server name.
     * @return session key.
     */
    Observable<String> getServerSessionKey(String serverName);

    /**
     * Hand shake with server.
     *
     * @param serverName server name
     */
    Observable<String> handShake(String serverName);
}
