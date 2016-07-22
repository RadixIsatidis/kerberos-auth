package net.yan.kerberos.client;

import net.yan.kerberos.config.ClientSettings;
import net.yan.kerberos.core.crypto.CryptoProvider;
import net.yan.kerberos.data.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * A client to performing sub-protocols:<br>
 * 1. Authentication service exchange. <br>
 * 2. Ticket granting service exchange. <br>
 * <p>
 * The client will not using a specific method to processing the certification and authorization request,
 * instead, it handles the request/response data only.<br>
 */
public class TicketGrantingClient {

    private static final Log log = LogFactory.getLog(TicketGrantingClient.class);

    private static final String TICKET_GRANTING_SERVER = "$$TICKET_GRANTING_SERVER";

    /**
     * Client settings.
     */
    private ClientSettings clientSettings;
    /**
     * Encrypt/Decrypt provider.
     */
    private CryptoProvider cryptoProvider;
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

    /**
     * An {@link AuthenticationServiceRequest} supplier, providing the capability of obtaining
     * an {@code AuthenticationServiceRequest} instance.
     */
    private Supplier<AuthenticationServiceRequest> authenticationServiceRequestSupplier;

    /**
     * An {@link AuthenticationServiceRequest} handler, providing the capability of obtaining an encrypted
     * {@link AuthenticationServiceResponse} by using an {@code AuthenticationServiceRequest} instance.
     */
    private Function<AuthenticationServiceRequest, String> authenticationServiceRequestFunction;

    /**
     * An {@link Authenticator} supplier, can obtain an {@code Authenticator} instance.
     */
    private Supplier<Authenticator> authenticatorSupplier;

    /**
     * A {@link TicketGrantingServiceRequest} handler, providing the capability of obtaining
     * an {@link TicketGrantingServiceResponse} by using an {@code TicketGrantingServiceRequest} instance.
     */
    private Function<TicketGrantingServiceRequest, TicketGrantingServiceResponse> ticketGrantingServiceRequestFunction;

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

    public CryptoProvider getCryptoProvider() {
        if (null == cryptoProvider)
            cryptoProvider = new CryptoProvider();
        return cryptoProvider;
    }

    public void setCryptoProvider(CryptoProvider cryptoProvider) {
        this.cryptoProvider = cryptoProvider;
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


    public void setAuthenticationServiceRequestSupplier(Supplier<AuthenticationServiceRequest> authenticationServiceRequestSupplier) {
        this.authenticationServiceRequestSupplier = authenticationServiceRequestSupplier;
    }

    public void setAuthenticationServiceRequestFunction(Function<AuthenticationServiceRequest, String> authenticationServiceRequestFunction) {
        this.authenticationServiceRequestFunction = authenticationServiceRequestFunction;
    }

    public void setAuthenticatorSupplier(Supplier<Authenticator> authenticatorSupplier) {
        this.authenticatorSupplier = authenticatorSupplier;
    }

    public void setTicketGrantingServiceRequestFunction(Function<TicketGrantingServiceRequest, TicketGrantingServiceResponse> ticketGrantingServiceRequestFunction) {
        this.ticketGrantingServiceRequestFunction = ticketGrantingServiceRequestFunction;
    }

    public void setServerTicketGrantingTicketFunction(Function<String, String> serverTicketGrantingTicketFunction) {
        this.serverTicketGrantingTicketFunction = serverTicketGrantingTicketFunction;
    }

    public TicketGrantingClient() {
    }


    private AuthenticationServiceResponse resolveAuthenticationServiceResponse(String string)
            throws GeneralSecurityException, ClassNotFoundException {
        return getCryptoProvider().decryptObject(string, getClientSettings().getMasterKey());
    }

    private String resolveServerSessionKey(String string, String rootSessionKey)
            throws ClassNotFoundException, GeneralSecurityException {
        return getCryptoProvider().decryptObject(string, rootSessionKey);
    }

    /**
     * Get server session key.
     *
     * @param serverName the server name.
     * @return session key.
     * @throws TicketGrantingTicketException
     */
    public String getServerSessionKey(String serverName) throws TicketGrantingTicketException {
        String sessionKey = getSessionKeyCache().get(serverName);
        int i = getClientSettings().getRetryTimes();
        while (null == sessionKey && i > 0) {
            try {
                getServerTicket(serverName);
                sessionKey = getSessionKeyCache().get(serverName);
            } catch (TicketGrantingTicketException ignored) {
            }
        }
        if (null == sessionKey)
            throw new TicketGrantingTicketException("Cannot get server session key: " + serverName);
        return sessionKey;
    }

    /**
     * Get server ticket.
     *
     * @param serverName the server name.
     * @return server ticket.
     * @throws TicketGrantingTicketException
     */
    public String getServerTicket(String serverName) throws TicketGrantingTicketException {
        String serverTicket = getServerTicketCache().get(serverName);
        if (null != serverTicket)
            return serverTicket;
        // 组Authenticator
        Authenticator authenticator = authenticatorSupplier.get();
        // TGT_SERVER
        String serverRootTicket = getServerRootTicket(serverName);
        // SK_TGS, must get it first.
        String rootSessionKey = getRootSessionKey();
        // TGT
        String rootTicket = getRootTicket();

        String encryptedAuth;
        try {
            encryptedAuth = getCryptoProvider().encryptObject(authenticator, rootSessionKey);
        } catch (GeneralSecurityException e) {
            log.error(e.getMessage());
            throw new TicketGrantingTicketException(e);
        }

        // get ST
        TicketGrantingServiceRequest request = new TicketGrantingServiceRequest();
        request.setAuthenticatorString(encryptedAuth);
        request.setClientTicketGrantingTicketString(rootTicket);
        request.setServerTicketGrantingTicketString(serverRootTicket);

        TicketGrantingServiceResponse response = ticketGrantingServiceRequestFunction.apply(request);
        String sessionKey;
        try {
            sessionKey = resolveServerSessionKey(response.getServerSessionKey(), rootSessionKey);
        } catch (ClassNotFoundException | GeneralSecurityException e) {
            log.error(e.getMessage());
            throw new TicketGrantingTicketException(e);
        }
        getSessionKeyCache().cache(serverName, sessionKey);

        serverTicket = response.getServerTicket();
        getServerTicketCache().cache(serverName, serverTicket);
        return serverTicket;
    }

    /**
     * Get server ticket granting ticket.
     *
     * @param serverName the server name.
     * @return ticket granting ticket belong to {@code serverName}
     * @throws TicketGrantingTicketException
     */
    public String getServerRootTicket(String serverName) throws TicketGrantingTicketException {
        String serverRootTicket = getTicketGrantingTicketCache().get(serverName);
        int i = getClientSettings().getRetryTimes();
        while (null == serverRootTicket && i > 0) {
            serverRootTicket = serverTicketGrantingTicketFunction.apply(serverName);
            getTicketGrantingTicketCache().cache(serverName, serverRootTicket);
            i--;
        }
        if (null == serverRootTicket)
            throw new TicketGrantingTicketException("Cannot get server root ticket: " + serverName);
        return serverRootTicket;
    }

    /**
     * Get TGT
     *
     * @return ticket granting ticket.
     * @throws TicketGrantingTicketException
     */
    public String getRootTicket() throws TicketGrantingTicketException {
        String rootTicket = getTicketGrantingTicketCache().get(TICKET_GRANTING_SERVER);
        if (null != rootTicket) {
            return rootTicket;
        }

        AuthenticationServiceRequest request = authenticationServiceRequestSupplier.get();
        String responseString = authenticationServiceRequestFunction.apply(request);
        AuthenticationServiceResponse response;
        try {
            response = resolveAuthenticationServiceResponse(responseString);
        } catch (GeneralSecurityException | ClassNotFoundException e) {
            log.error(e.getMessage());
            throw new TicketGrantingTicketException(e);
        }
        rootTicket = response.getTicketGrantingTicket();
        getTicketGrantingTicketCache().cache(TICKET_GRANTING_SERVER, rootTicket); // TGT
        getSessionKeyCache().cache(TICKET_GRANTING_SERVER, response.getSessionKey()); // SK_TGS
        return rootTicket;
    }

    /**
     * Get TGT_TGS
     *
     * @return TGT
     * @throws TicketGrantingTicketException
     */
    public String getRootSessionKey() throws TicketGrantingTicketException {
        String rootSessionKey = getSessionKeyCache().get(TICKET_GRANTING_SERVER);
        int i = getClientSettings().getRetryTimes();
        while (null == rootSessionKey && i > 0) {
            try {
                getRootTicket();
                rootSessionKey = getSessionKeyCache().get(TICKET_GRANTING_SERVER);
            } catch (TicketGrantingTicketException ignored) {
            }
            i--;
        }
        if (null == rootSessionKey)
            throw new TicketGrantingTicketException("Cannot resolve root session key.");
        return rootSessionKey;
    }
}
