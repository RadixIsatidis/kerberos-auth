package net.yan.kerberos.client;

import net.yan.kerberos.core.KerberosException;
import net.yan.kerberos.data.ClientServerExchangeRequest;
import net.yan.kerberos.data.ClientServerExchangeResponse;

/**
 * @author yanle
 */
public interface ServerHelper {
    /**
     * Get TGT
     *
     * @return ticket granting ticket.
     * @throws KerberosException any exception
     */
    String getRootTicket() throws KerberosException;

    /**
     * Hand shake with client.
     *
     * @param request request
     * @return response
     * @throws KerberosException any exception.
     */
    ClientServerExchangeResponse handShake(ClientServerExchangeRequest request) throws KerberosException;
}
