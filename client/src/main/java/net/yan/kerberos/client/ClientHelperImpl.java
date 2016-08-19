package net.yan.kerberos.client;

import com.google.common.base.Strings;
import net.yan.kerberos.client.as.AuthenticationClient;
import net.yan.kerberos.client.core.ClientSettings;
import net.yan.kerberos.client.cs.ClientServerExchangeClient;
import net.yan.kerberos.client.tgc.TicketGrantingClient;
import net.yan.kerberos.client.tgc.TicketGrantingServiceResponseWrapper;
import net.yan.kerberos.core.KerberosCryptoException;
import net.yan.kerberos.core.KerberosException;
import net.yan.kerberos.data.AuthenticationServiceResponse;
import net.yan.kerberos.data.TicketGrantingTicket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import rx.Observable;
import rx.schedulers.Schedulers;

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
public class ClientHelperImpl implements ClientHelper {

    private static final Logger log = LoggerFactory.getLogger(ClientHelperImpl.class);

    private static final String TICKET_GRANTING_SERVER = "$$TICKET_GRANTING_SERVER";

    /**
     * Client settings.
     */
    private final ClientSettings clientSettings;
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

    private final AuthenticationClient authenticationClient;

    private final TicketGrantingClient ticketGrantingClient;

    private final ClientServerExchangeClient clientServerExchangeClient;

    /**
     * A server {@link TicketGrantingTicket} supplier, can obtain an encrypted server {@code TicketGrantingTicket}
     * string by using the server name.
     */
    private final Function<String, String> serverTicketGrantingTicketFunction;

    public ClientSettings getClientSettings() {
        return clientSettings;
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

    private Observable<String> getTicketGrantingTicketCache(String key) {
        return Observable.create(subscriber -> {
            String serverRootTicket = getTicketGrantingTicketCache().get(key);
            if (!Strings.isNullOrEmpty(serverRootTicket))
                subscriber.onNext(serverRootTicket);
            subscriber.onCompleted();
        });
    }

    public void setTicketGrantingTicketCache(CacheProvider ticketGrantingTicketCache) {
        this.ticketGrantingTicketCache = ticketGrantingTicketCache;
    }

    private CacheProvider getSessionKeyCache() {
        if (null == sessionKeyCache)
            sessionKeyCache = getInternalCache();
        return sessionKeyCache;
    }

    private Observable<String> getSessionKeyCache(String key) {
        return Observable.create(subscriber -> {
            String serverRootTicket = getSessionKeyCache().get(key);
            if (!Strings.isNullOrEmpty(serverRootTicket))
                subscriber.onNext(serverRootTicket);
            subscriber.onCompleted();
        });
    }

    public void setSessionKeyCache(CacheProvider sessionKeyCache) {
        this.sessionKeyCache = sessionKeyCache;
    }

    private CacheProvider getServerTicketCache() {
        if (null == serverTicketCache)
            serverTicketCache = getInternalCache();
        return serverTicketCache;
    }

    private Observable<String> getServerTicketCache(String key) {
        return Observable.create(subscriber -> {
            String serverRootTicket = getServerTicketCache().get(key);
            if (!Strings.isNullOrEmpty(serverRootTicket))
                subscriber.onNext(serverRootTicket);
            subscriber.onCompleted();
        });
    }

    public void setServerTicketCache(CacheProvider serverTicketCache) {
        this.serverTicketCache = serverTicketCache;
    }

    public ClientHelperImpl(ClientSettings clientSettings,
                            AuthenticationClient authenticationClient,
                            TicketGrantingClient ticketGrantingClient,
                            ClientServerExchangeClient clientServerExchangeClient,
                            Function<String, String> serverTicketGrantingTicketFunction) {
        this.clientSettings = clientSettings;
        this.authenticationClient = authenticationClient;
        this.ticketGrantingClient = ticketGrantingClient;
        this.clientServerExchangeClient = clientServerExchangeClient;
        this.serverTicketGrantingTicketFunction = serverTicketGrantingTicketFunction;
    }

    @Override
    public Observable<String> getServerSessionKey(String serverName) {
        Observable<String> fromCache = getSessionKeyCache(serverName);
        Observable<String> fromServer = getServerTicket(serverName)
                .flatMap(s -> getSessionKeyCache(serverName));

        return Observable.concat(fromCache, fromServer)
                .first()
                .take(1);
    }

    /**
     * Get server ticket.
     *
     * @param serverName the server name.
     * @return server ticket.
     */
    public Observable<String> getServerTicket(String serverName) {
        Observable<String> fromCache = getServerTicketCache(serverName);
        return Observable
                .concat(fromCache, _getServerTicket(serverName))
                .first();
    }

    private Observable<String> getServerTicket(Entity1 e, String serverName) {
        return ticketGrantingClient.ticketGrantingServiceExchange(e.TGT_SERVER, e.SK_TGS, e.TGT_TGS)
                .doOnNext((wrapper) -> {
                    getSessionKeyCache().cache(serverName, wrapper.getServerSessionKey());
                    getServerTicketCache().cache(serverName, wrapper.getServerTicket());
                })
                .map(TicketGrantingServiceResponseWrapper::getServerTicket);
    }

    private Observable<String> _getServerTicket(String serverName) {
        return Observable.combineLatest(
                getServerRootTicket(serverName), // TGT_SERVER
                getRootSessionKey(), // SK_TGS
                getRootTicket(), // TGT_TGS
                (TGT_SERVER, SK_TGS, TGT_TGS) -> {
                    Entity1 e = new Entity1();
                    e.TGT_SERVER = TGT_SERVER;
                    e.SK_TGS = SK_TGS;
                    e.TGT_TGS = TGT_TGS;
                    return e;
                }
        ).take(1).flatMap(e ->
                // get ST
                getServerTicket(e, serverName)
        ).take(1);
    }

    /**
     * Get server ticket granting ticket.
     *
     * @param serverName the server name.
     * @return ticket granting ticket belong to {@code serverName}
     */
    public Observable<String> getServerRootTicket(String serverName) {
        Observable<String> fromCache = getTicketGrantingTicketCache(serverName);
        Observable<String> fromTGSServer = Observable.create((Observable.OnSubscribe<String>) subscriber -> {
            String serverRootTicket = serverTicketGrantingTicketFunction.apply(serverName);
            if (Strings.isNullOrEmpty(serverRootTicket)) {
                subscriber.onError(new KerberosException("Cannot get server root ticket: " + serverName));
            } else {
                subscriber.onNext(serverRootTicket);
                subscriber.onCompleted();
            }
        }).doOnNext((String serverRootTicket) -> {
            getTicketGrantingTicketCache().cache(serverName, serverRootTicket);
        });
        return Observable.concat(fromCache, fromTGSServer).first();
    }

    /**
     * Get TGT
     *
     * @return ticket granting ticket.
     */
    public Observable<String> getRootTicket() {
        Observable<String> fromCache = getTicketGrantingTicketCache(TICKET_GRANTING_SERVER);
        Observable<String> fromASExchange = authenticationClient.authenticationServiceExchange().doOnNext(response -> {
            String rootTicket = response.getTicketGrantingTicket();
            getTicketGrantingTicketCache().cache(TICKET_GRANTING_SERVER, rootTicket); // TGT
            getSessionKeyCache().cache(TICKET_GRANTING_SERVER, response.getSessionKey()); // SK_TGS
        }).map(AuthenticationServiceResponse::getTicketGrantingTicket);
        return Observable.concat(fromCache, fromASExchange).first();
    }

    /**
     * Get TGT_TGS
     *
     * @return TGT
     */
    public Observable<String> getRootSessionKey() {
        Observable<String> fromCache = Observable.create(subscriber -> {
            String rootSessionKey = getSessionKeyCache().get(TICKET_GRANTING_SERVER);
            if (!Strings.isNullOrEmpty(rootSessionKey)) {
                subscriber.onNext(rootSessionKey);
            }
            subscriber.onCompleted();
        });
        return Observable
                .concat(fromCache, getRootTicket().flatMap(s -> fromCache))
                .last();
    }

    @Override
    public Observable<String> handShake(String serverName) {
        if (log.isDebugEnabled())
            log.debug("Hand shake with; " + serverName);
        return Observable
                .combineLatest(
                        getServerSessionKey(serverName),
                        getServerTicket(serverName),
                        (a, b) -> {
                            Entity2 e = new Entity2();
                            e.SK_SERVER = a;
                            e.ST = b;
                            return e;
                        }
                )
                .flatMap(entity2 -> clientServerExchangeClient.clientServerExchange(serverName, entity2.SK_SERVER, entity2.ST))
                .subscribeOn(Schedulers.io());
    }

    private class Entity1 {
        private String TGT_SERVER;

        private String SK_TGS;

        private String TGT_TGS;
    }

    private class Entity2 {
        private String SK_SERVER;

        private String ST;
    }
}
