package net.yan.kerberos.client.tgc;

import net.yan.kerberos.core.KerberosException;
import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.TicketGrantingServiceRequest;
import net.yan.kerberos.data.TicketGrantingServiceResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.GeneralSecurityException;
import java.util.function.Function;
import java.util.function.Supplier;

public class TicketGrantingClient {

    private static final Log log = LogFactory.getLog(TicketGrantingClient.class);

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

    private String decrypt(String string, String rootSessionKey)
            throws ClassNotFoundException, GeneralSecurityException {
        return getCipherProvider().decryptObject(string, rootSessionKey);
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
        // 组Authenticator
        Authenticator authenticator = authenticatorSupplier.get();
        String encryptedAuth;
        try {
            encryptedAuth = getCipherProvider().encryptObject(authenticator, rootSessionKey);
        } catch (GeneralSecurityException e) {
            log.error(e.getMessage());
            throw new KerberosException(e);
        }

        // get ST
        TicketGrantingServiceRequest request = new TicketGrantingServiceRequest();
        request.setAuthenticatorString(encryptedAuth);
        request.setClientTicketGrantingTicketString(rootTicket);
        request.setServerTicketGrantingTicketString(serverRootTicket);

        TicketGrantingServiceResponse response = ticketGrantingServiceRequestFunction.apply(request);

        String sessionKey;
        try {
            sessionKey = decrypt(response.getServerSessionKey(), rootSessionKey);
        } catch (ClassNotFoundException | GeneralSecurityException e) {
            log.error(e.getMessage());
            throw new KerberosException(e);
        }

        TicketGrantingServiceResponseWrapper wrapper = new TicketGrantingServiceResponseWrapper();
        wrapper.setServerSessionKey(sessionKey);
        wrapper.setServerTicket(response.getServerTicket());
        return wrapper;
    }
}
