package net.yan.kerberos.client;

import net.yan.kerberos.client.as.AuthenticationClient;
import net.yan.kerberos.client.core.ClientSettings;
import net.yan.kerberos.client.cs.ClientServerExchangeServer;
import net.yan.kerberos.core.KerberosException;
import net.yan.kerberos.data.AuthenticationServiceResponse;
import net.yan.kerberos.data.ClientServerExchangeRequest;
import net.yan.kerberos.data.ClientServerExchangeResponse;

import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * A server side helper.
 */
public class ServerHelperImpl implements ServerHelper {

    private static final String TGT_KEY = "$$SERVER-TGT-KEY";

    private static final String SESSION_KEY = "$$SERVER-KDC-SESSION-KEY";

    /**
     * Client settings.
     */
    private ClientSettings clientSettings;

    /**
     * Using to request server-side TGT
     */
    private AuthenticationClient authenticationClient;

    /**
     * Using to authenticate client.
     */
    private ClientServerExchangeServer clientServerExchangeServer;

    /**
     * An TGT_SERVER supplier.
     */
    private Supplier<String> serverTGTSupplier;

    /**
     * Using to cache TGT_SERVER
     */
    private Consumer<String> serverTGTCache;

    /**
     * Using to cache SK_TGS
     */
    private Supplier<String> rootSessionSupplier;

    /**
     * Using to cache SK_TGS
     */
    private Consumer<String> rootSessionCache;

    public ClientSettings getClientSettings() {
        return clientSettings;
    }

    public void setClientSettings(ClientSettings clientSettings) {
        this.clientSettings = clientSettings;
    }

    public void setAuthenticationClient(AuthenticationClient authenticationClient) {
        this.authenticationClient = authenticationClient;
    }

    public void setClientServerExchangeServer(ClientServerExchangeServer clientServerExchangeServer) {
        this.clientServerExchangeServer = clientServerExchangeServer;
    }

    public void setCache(CacheProvider cache) {
        serverTGTSupplier = () -> cache.get(TGT_KEY);
        serverTGTCache = (s) -> cache.cache(TGT_KEY, s);
        rootSessionSupplier = () -> cache.get(SESSION_KEY);
        rootSessionCache = (s) -> cache.cache(SESSION_KEY, s);
    }


    /**
     * Get TGT_TGS
     *
     * @return TGT
     * @throws KerberosException any exception.
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

    @Override
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

    @Override
    public ClientServerExchangeResponse handShake(ClientServerExchangeRequest request) throws KerberosException {
        return clientServerExchangeServer.clientServerExchange(
                request,
                getClientSettings().getLocalName(),
                getRootSessionKey()
        );
    }
}
