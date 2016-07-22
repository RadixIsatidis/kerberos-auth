package net.yan.kerberos.tgc;

import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.TicketGrantingTicket;

import java.time.Instant;
import java.util.Objects;

/**
 * A default {@link AuthenticatorVerifyProvider} implement.
 */
public class DefaultAuthenticatorVerifyProvider implements AuthenticatorVerifyProvider {

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify(TicketGrantingTicket ticketGrantingTicket, Authenticator authenticator) {
        long t = ticketGrantingTicket.getStartTime() + ticketGrantingTicket.getLifeTime();
        Instant now = Instant.now();
        Instant after = Instant.ofEpochMilli(t);
        return now.isBefore(after)
                && Objects.equals(ticketGrantingTicket.getUsername(), authenticator.getUsername());
    }
}
