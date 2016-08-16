package net.yan.kerberos.client;

import net.yan.kerberos.core.KerberosException;

/**
 * @author yanle
 */
public interface ClientHelper {
    /**
     * Get server session key.
     *
     * @param serverName the server name.
     * @return session key.
     * @throws KerberosException any exception.
     */
    String getServerSessionKey(String serverName) throws KerberosException;

    /**
     * Hand shake with server.
     *
     * @param serverName server name
     * @throws KerberosException any exception.
     */
    void handShake(String serverName) throws KerberosException;
}
