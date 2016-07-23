package net.yan.kerberos.client.tgc;

import net.yan.kerberos.core.KerberosCryptoException;
import net.yan.kerberos.core.KerberosException;
import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.TicketGrantingServiceRequest;
import net.yan.kerberos.data.TicketGrantingServiceResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.util.function.Function;
import java.util.function.Supplier;

public class TicketGrantingClient {

    private static final Logger log = LoggerFactory.getLogger(TicketGrantingClient.class);

    /**
     * Encrypt/Decrypt provider.
     */
    private CipherProvider cipherProvider;

    /**
     * An {@link Authenticator} supplier, can obtain an {@code Authenticator} instance.
     */
    private Supplier<Authenticator> authenticatorSupplier;

    /**
     * A {@link TicketGrantingServiceRequest} handler, providing the capability of obtaining
     * an {@link TicketGrantingServiceResponse} by using an {@code TicketGrantingServiceRequest} instance.
     */
    private Function<TicketGrantingServiceRequest, TicketGrantingServiceResponse> ticketGrantingServiceRequestFunction;

    public CipherProvider getCipherProvider() {
        if (null == cipherProvider)
            cipherProvider = new CipherProvider();
        return cipherProvider;
    }

    public void setCipherProvider(CipherProvider cipherProvider) {
        this.cipherProvider = cipherProvider;
    }

    public void setAuthenticatorSupplier(Supplier<Authenticator> authenticatorSupplier) {
        this.authenticatorSupplier = authenticatorSupplier;
    }

    public void setTicketGrantingServiceRequestFunction(Function<TicketGrantingServiceRequest, TicketGrantingServiceResponse> ticketGrantingServiceRequestFunction) {
        this.ticketGrantingServiceRequestFunction = ticketGrantingServiceRequestFunction;
    }

    private String decrypt(String key, String secret)
            throws ClassNotFoundException, GeneralSecurityException {
        return getCipherProvider().decryptString(secret, getCipherProvider().generateKey(key));
    }

    private String encrypt(Authenticator authenticator, String rootSessionKey)
            throws GeneralSecurityException {
        return getCipherProvider().encryptObject(authenticator, rootSessionKey);
    }

    /**
     * Ticket granting service exchange.
     *
     * @param serverRootTicket TGT_SERVER
     * @param rootSessionKey   SK_KDC
     * @param rootTicket       TGT_KDC
     * @return ticket granting service exchange response.
     * @throws KerberosException
     */
    public TicketGrantingServiceResponseWrapper ticketGrantingServiceExchange(
            String serverRootTicket,
            String rootSessionKey,
            String rootTicket
    ) throws KerberosException {
        log.info(String.format("Ticket Granting Service Exchange: TGT_SERVER: [%s], SK_TGS: [%s], TGT_TGS:[%s]",
                serverRootTicket, rootSessionKey, rootTicket));
        // 组Authenticator
        Authenticator authenticator = authenticatorSupplier.get();
        if (log.isDebugEnabled())
            log.debug("Create client Authenticator: " + authenticator);
        String encryptedAuth;
        try {
            encryptedAuth = encrypt(authenticator, rootSessionKey);
            if (log.isDebugEnabled())
                log.debug("Encrypted client Authenticator: " + encryptedAuth);
        } catch (GeneralSecurityException e) {
            throw new KerberosCryptoException(e);
        }

        // get ST
        TicketGrantingServiceRequest request = new TicketGrantingServiceRequest();
        request.setAuthenticatorString(encryptedAuth);
        request.setClientTicketGrantingTicketString(rootTicket);
        request.setServerTicketGrantingTicketString(serverRootTicket);
        if (log.isDebugEnabled())
            log.debug("Create TicketGrantingServiceRequest: " + request);

        TicketGrantingServiceResponse response = ticketGrantingServiceRequestFunction.apply(request);
        if (log.isDebugEnabled())
            log.debug("Receive TicketGrantingServiceResponse: " + response);

        String sessionKey;
        try {
            sessionKey = decrypt(rootSessionKey, response.getServerSessionKey());
            if (log.isDebugEnabled())
                log.debug("Decrypted SK_SERVER: " + sessionKey);
        } catch (ClassNotFoundException | GeneralSecurityException e) {
            throw new KerberosCryptoException(e);
        }

        TicketGrantingServiceResponseWrapper wrapper = new TicketGrantingServiceResponseWrapper();
        wrapper.setServerSessionKey(sessionKey);
        wrapper.setServerTicket(response.getServerTicket());
        return wrapper;
    }
}
