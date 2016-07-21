package net.yan.kerberos.client;

import net.yan.kerberos.config.ClientSettings;
import net.yan.kerberos.core.crypto.CryptoProvider;
import net.yan.kerberos.data.AuthenticationServiceResponse;
import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.TicketGrantingServiceRequest;
import net.yan.kerberos.data.TicketGrantingServiceResponse;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;

public class TicketGrantingClient {

    private static final String TICKET_GRANTING_SERVER = "$$TICKET_GRANTING_SERVER";

    private ClientSettings clientSettings;

    public ClientSettings getClientSettings() {
        return clientSettings;
    }

    public void setClientSettings(ClientSettings clientSettings) {
        this.clientSettings = clientSettings;
    }

    private CryptoProvider cryptoProvider;

    public CryptoProvider getCryptoProvider() {
        return cryptoProvider;
    }

    public void setCryptoProvider(CryptoProvider cryptoProvider) {
        this.cryptoProvider = cryptoProvider;
    }

    /**
     * Ticket Granting Ticket cache.
     */
    private DataCache ticketGrantingTicketCache;

    public DataCache getTicketGrantingTicketCache() {
        return ticketGrantingTicketCache;
    }

    public void setTicketGrantingTicketCache(DataCache ticketGrantingTicketCache) {
        this.ticketGrantingTicketCache = ticketGrantingTicketCache;
    }

    /**
     * Session key cache.
     */
    private DataCache sessionKeyCache;

    public DataCache getSessionKeyCache() {
        return sessionKeyCache;
    }

    public void setSessionKeyCache(DataCache sessionKeyCache) {
        this.sessionKeyCache = sessionKeyCache;
    }

    private DataCache serverTicketCache;

    public DataCache getServerTicketCache() {
        return serverTicketCache;
    }

    public void setServerTicketCache(DataCache serverTicketCache) {
        this.serverTicketCache = serverTicketCache;
    }

    public AuthenticationServiceResponse resolveAuthenticationServiceResponse(String string)
            throws IOException, GeneralSecurityException, ClassNotFoundException {
        AuthenticationServiceResponse response = getCryptoProvider().decryptObject(string, getClientSettings().getMasterKey());
        getTicketGrantingTicketCache().cache(TICKET_GRANTING_SERVER, response.getTicketGrantingTicket());
        getSessionKeyCache().cache(TICKET_GRANTING_SERVER, response.getSessionKey());
        return response;
    }

    public TicketGrantingServiceRequest createTicketGrantingServiceRequest(
            Authenticator authenticator,
            String serverName
    ) throws IOException, GeneralSecurityException {
        authenticator.setStartTime(Instant.now().toEpochMilli());
        authenticator.setLifeTime(getClientSettings().getSessionLifeTime());

        TicketGrantingServiceRequest request = new TicketGrantingServiceRequest();
        request.setAuthenticatiorString(getCryptoProvider().encryptObject(authenticator, getSessionKeyCache().get(TICKET_GRANTING_SERVER)));
        request.setClientTicketGrantingTicketString(getTicketGrantingTicketCache().get(TICKET_GRANTING_SERVER));
        request.setServerTicketGrantingTicketString(getTicketGrantingTicketCache().get(serverName));
        return request;
    }

    public void resolveTicketGrantingServiceResponse(
            TicketGrantingServiceResponse response,
            String serverName
    ) throws IOException, GeneralSecurityException, ClassNotFoundException {
        String sessionKey = getCryptoProvider().decryptObject(response.getServerSessionKey(), getSessionKeyCache().get(TICKET_GRANTING_SERVER));
        getSessionKeyCache().cache(serverName, sessionKey);
        getServerTicketCache().cache(serverName, response.getServerTicket());
    }
}
