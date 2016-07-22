package net.yan.kerberos.tgc;

import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.TicketGrantingTicket;

/**
 * Class that defines API used by {@link TicketGrantingService}
 */
public interface AuthenticatorVerifyProvider {

    /**
     * Verify user info.
     *
     * @param ticketGrantingTicket client ticket granting ticket.
     * @param authenticator        client authenticator.
     * @return {@code true} if verify success, {@code false} else.
     */
    boolean verify(TicketGrantingTicket ticketGrantingTicket, Authenticator authenticator);
}
