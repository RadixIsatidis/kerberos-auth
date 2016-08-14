package net.yan.kerberos.client;

import net.yan.kerberos.client.as.AuthenticationClient;
import net.yan.kerberos.client.core.ClientSettings;
import net.yan.kerberos.client.cs.ClientServerExchangeClient;
import net.yan.kerberos.client.tgc.TicketGrantingClient;
import net.yan.kerberos.client.tgc.TicketGrantingServiceResponseWrapper;
import net.yan.kerberos.core.KerberosException;
import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.data.AuthenticationServiceResponse;
import net.yan.kerberos.data.TicketGrantingTicket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * A client to performing sub-protocols:<br>
 * 1. Authentication service exchange. {@link #getRootSessionKey()} -&gt; {@link #getRootTicket()} <br>
 * 2. Ticket granting service exchange. {@link #getServerTicket(String)} -&gt; {@link #getServerRootTicket(String)} <br>
 * 3. Client-Server exchange  {@link #getServerSessionKey(String)}<br>
 * <p>
 * The client will not using a specific method to processing the certification and authorization request,
 * instead, it handles the request/response data only.<br>
 */
public class ClientHelper {

    private static final Logger log = LoggerFactory.getLogger(ClientHelper.class);

    private static final String TICKET_GRANTING_SERVER = "$$TICKET_GRANTING_SERVER";

    /**
     * Client settings.
     */
    private ClientSettings clientSettings;
    /**
     * Encrypt/Decrypt provider.
     */
    private CipherProvider cipherProvider;
    /**
     * TGT(Ticket Granting Ticket) cache. Including TGT_TGS and TGT_SERVER
     */
    private CacheProvider ticketGrantingTicketCache;
    /**
     * SK(Session key) cache. Including SK_TGS and SK_SERVER
     */
    private CacheProvider sessionKeyCache;
    /**
     * ST(Server ticket) cache.
     */
    private CacheProvider serverTicketCache;

    private AuthenticationClient authenticationClient;

    private TicketGrantingClient ticketGrantingClient;

    private ClientServerExchangeClient clientServerExchangeClient;

    /**
     * A server {@link TicketGrantingTicket} supplier, can obtain an encrypted server {@code TicketGrantingTicket}
     * string by using the server name.
     */
    private Function<String, String> serverTicketGrantingTicketFunction;

    public ClientSettings getClientSettings() {
        return clientSettings;
    }

    public void setClientSettings(ClientSettings clientSettings) {
        this.clientSettings = clientSettings;
    }

    public CipherProvider getCipherProvider() {
        if (null == cipherProvider)
            cipherProvider = new CipherProvider();
        return cipherProvider;
    }

    public void setCipherProvider(CipherProvider cipherProvider) {
        this.cipherProvider = cipherProvider;
    }

    private CacheProvider getInternalCache() {
        return new CacheProvider() {
            private Map<String, String> _map = new HashMap<>();

            @Override
            public String cache(String key, String data) {
                _map.put(key, data);
                return data;
            }

            @Override
            public String get(String key) {
                return _map.get(key);
            }
        };
    }

    private CacheProvider getTicketGrantingTicketCache() {
        if (null == ticketGrantingTicketCache)
            ticketGrantingTicketCache = getInternalCache();
        return ticketGrantingTicketCache;
    }

    public void setTicketGrantingTicketCache(CacheProvider ticketGrantingTicketCache) {
        this.ticketGrantingTicketCache = ticketGrantingTicketCache;
    }

    private CacheProvider getSessionKeyCache() {
        if (null == sessionKeyCache)
            sessionKeyCache = getInternalCache();
        return sessionKeyCache;
    }

    public void setSessionKeyCache(CacheProvider sessionKeyCache) {
        this.sessionKeyCache = sessionKeyCache;
    }

    private CacheProvider getServerTicketCache() {
        if (null == serverTicketCache)
            serverTicketCache = getInternalCache();
        return serverTicketCache;
    }

    public void setServerTicketCache(CacheProvider serverTicketCache) {
        this.serverTicketCache = serverTicketCache;
    }

    public void setAuthenticationClient(AuthenticationClient authenticationClient) {
        this.authenticationClient = authenticationClient;
    }

    public void setTicketGrantingClient(TicketGrantingClient ticketGrantingClient) {
        this.ticketGrantingClient = ticketGrantingClient;
    }

    public void setClientServerExchangeClient(ClientServerExchangeClient clientServerExchangeClient) {
        this.clientServerExchangeClient = clientServerExchangeClient;
    }

    public void setServerTicketGrantingTicketFunction(Function<String, String> serverTicketGrantingTicketFunction) {
        this.serverTicketGrantingTicketFunction = serverTicketGrantingTicketFunction;
    }

    public ClientHelper() {
    }

    /**
     * Get server session key.
     *
     * @param serverName the server name.
     * @return session key.
     * @throws KerberosException
     */
    public String getServerSessionKey(String serverName) throws KerberosException {
        String sessionKey = getSessionKeyCache().get(serverName);
        int i = getClientSettings().getRetryTimes();
        while (null == sessionKey && i > 0) {
            try {
                getServerTicket(serverName);
                sessionKey = getSessionKeyCache().get(serverName);
            } catch (KerberosException ignored) {
            }
        }
        if (null == sessionKey)
            throw new KerberosException("Cannot get server session key: " + serverName);
        return sessionKey;
    }

    /**
     * Get server ticket.
     *
     * @param serverName the server name.
     * @return server ticket.
     * @throws KerberosException
     */
    public String getServerTicket(String serverName) throws KerberosException {
        String serverTicket = getServerTicketCache().get(serverName);
        if (null != serverTicket)
            return serverTicket;
        // TGT_SERVER
        String serverRootTicket = getServerRootTicket(serverName);
        // SK_TGS, must get it first.
        String rootSessionKey = getRootSessionKey();
        // TGT
        String rootTicket = getRootTicket();
        // get ST
        TicketGrantingServiceResponseWrapper wrapper = ticketGrantingClient.ticketGrantingServiceExchange(serverRootTicket, rootSessionKey, rootTicket);
        getSessionKeyCache().cache(serverName, wrapper.getServerSessionKey());

        serverTicket = wrapper.getServerTicket();
        getServerTicketCache().cache(serverName, serverTicket);
        return serverTicket;
    }

    /**
     * Get server ticket granting ticket.
     *
     * @param serverName the server name.
     * @return ticket granting ticket belong to {@code serverName}
     * @throws KerberosException
     */
    public String getServerRootTicket(String serverName) throws KerberosException {
        String serverRootTicket = getTicketGrantingTicketCache().get(serverName);
        int i = getClientSettings().getRetryTimes();
        while (null == serverRootTicket && i > 0) {
            serverRootTicket = serverTicketGrantingTicketFunction.apply(serverName);
            getTicketGrantingTicketCache().cache(serverName, serverRootTicket);
            i--;
        }
        if (null == serverRootTicket)
            throw new KerberosException("Cannot get server root ticket: " + serverName);
        return serverRootTicket;
    }

    /**
     * Get TGT
     *
     * @return ticket granting ticket.
     * @throws KerberosException
     */
    public String getRootTicket() throws KerberosException {
        String rootTicket = getTicketGrantingTicketCache().get(TICKET_GRANTING_SERVER);
        if (null != rootTicket) {
            return rootTicket;
        }

        AuthenticationServiceResponse response = authenticationClient.authenticationServiceExchange();
        rootTicket = response.getTicketGrantingTicket();
        getTicketGrantingTicketCache().cache(TICKET_GRANTING_SERVER, rootTicket); // TGT
        getSessionKeyCache().cache(TICKET_GRANTING_SERVER, response.getSessionKey()); // SK_TGS
        return rootTicket;
    }

    /**
     * Get TGT_TGS
     *
     * @return TGT
     * @throws KerberosException
     */
    public String getRootSessionKey() throws KerberosException {
        String rootSessionKey = getSessionKeyCache().get(TICKET_GRANTING_SERVER);
        int i = getClientSettings().getRetryTimes();
        while (null == rootSessionKey && i > 0) {
            try {
                getRootTicket();
                rootSessionKey = getSessionKeyCache().get(TICKET_GRANTING_SERVER);
            } catch (KerberosException ignored) {
            }
            i--;
        }
        if (null == rootSessionKey)
            throw new KerberosException("Cannot resolve root session key.");
        return rootSessionKey;
    }

    public void handShake(String serverName) throws KerberosException {
        String serverSessionKey = getServerSessionKey(serverName);
        String serverTicket = getServerTicket(serverName);

        clientServerExchangeClient.clientServerExchange(serverName, serverSessionKey, serverTicket);
    }
}
