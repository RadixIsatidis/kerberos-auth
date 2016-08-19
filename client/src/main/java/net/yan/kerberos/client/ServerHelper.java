package net.yan.kerberos.client;

import net.yan.kerberos.data.ClientServerExchangeRequest;
import net.yan.kerberos.data.ClientServerExchangeResponse;
import rx.Observable;

/**
 * @author yanle
 */
public interface ServerHelper {
    /**
     * Get TGT
     *
     * @return ticket granting ticket.
     */
    Observable<String> getRootTicket();

    /**
     * Hand shake with client.
     * <p>
     * Will throw {@code KerberosException} if any exception
     *
     * @param request request
     * @return response.
     */
    Observable<ClientServerExchangeResponse> handShake(ClientServerExchangeRequest request);
}
