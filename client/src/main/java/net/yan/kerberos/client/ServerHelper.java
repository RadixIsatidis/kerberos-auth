package net.yan.kerberos.client;

import net.yan.kerberos.client.as.AuthenticationClient;
import net.yan.kerberos.client.core.ClientSettings;
import net.yan.kerberos.client.cs.ClientServerExchangeServer;
import net.yan.kerberos.core.KerberosException;
import net.yan.kerberos.data.AuthenticationServiceResponse;
import net.yan.kerberos.data.ClientServerExchangeRequest;

import java.util.function.Consumer;
import java.util.function.Supplier;

public class ServerHelper {

    /**
     * Client settings.
     */
    private ClientSettings clientSettings;


    private AuthenticationClient authenticationClient;

    private ClientServerExchangeServer clientServerExchangeServer;

    /**
     * An TGT_SERVER supplier.
     */
    private Supplier<String> serverTGTSupplier;

    private Consumer<String> serverTGTCache;

    private Supplier<String> rootSessionSupplier;

    private Consumer<String> rootSessionCache;

    public ClientSettings getClientSettings() {
        return clientSettings;
    }

    public void setClientSettings(ClientSettings clientSettings) {
        this.clientSettings = clientSettings;
    }

    /**
     * Get TGT_TGS
     *
     * @return TGT
     * @throws KerberosException
     */
    public String getRootSessionKey() throws KerberosException {
        String rootSessionKey = rootSessionSupplier.get();
        int i = getClientSettings().getRetryTimes();
        while (null == rootSessionKey && i > 0) {
            try {
                getRootTicket();
                rootSessionKey = rootSessionSupplier.get();
            } catch (KerberosException ignored) {
            }
            i--;
        }
        if (null == rootSessionKey)
            throw new KerberosException("Cannot resolve root session key.");
        return rootSessionKey;
    }

    /**
     * Get TGT
     *
     * @return ticket granting ticket.
     * @throws KerberosException
     */
    public String getRootTicket() throws KerberosException {
        String rootTicket = serverTGTSupplier.get();
        if (null != rootTicket) {
            return rootTicket;
        }

        AuthenticationServiceResponse response = authenticationClient.authenticationServiceExchange();
        rootTicket = response.getTicketGrantingTicket();
        serverTGTCache.accept(rootTicket); // TGT
        rootSessionCache.accept(response.getSessionKey()); // SK_TGS
        return rootTicket;
    }

    public void handShake(ClientServerExchangeRequest request) throws KerberosException {
        clientServerExchangeServer.clientServerExchange(
                request,
                getClientSettings().getLocalName(),
                getRootSessionKey()
        );
    }
}
