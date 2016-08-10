package net.yan.kerberos.examples.client;

import net.yan.kerberos.data.*;
import net.yan.kerberos.examples.userdetails.UserDetailsImpl;
import net.yan.kerberos.kdc.userdetails.UserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;

/**
 * @author yanle
 */
@Repository
public class AuthenticationServerDao {

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private ClientProperties properties;

    @Autowired
    private UserDetailsService userDetailsService;

    @SuppressWarnings("Duplicates")
    public AuthenticationServiceRequest createRequest() {
        AuthenticationServiceRequest request = new AuthenticationServiceRequest();
        request.setUsername(properties.getLocalName());
        request.setAddress(properties.getLocalhost());
        request.setLifeTime(properties.getSessionLifeTime());
        request.setStartTime(Instant.now().toEpochMilli());
        return request;
    }


    public String resolveAuthenticationRequest(AuthenticationServiceRequest request) {
        String url = UriComponentsBuilder
                .newInstance()
                .host(properties.getAuthenticationServerName())
                .pathSegment("kdc", "auth")
                .scheme("http")
                .build()
                .toString();

        return restTemplate.postForObject(url, request, String.class);
    }

    @SuppressWarnings("Duplicates")
    public Authenticator createAuthenticator() {
        Authenticator authenticator = new Authenticator();
        authenticator.setUsername(properties.getLocalName());
        authenticator.setAddress(properties.getLocalhost());
        authenticator.setStartTime(Instant.now().toEpochMilli());
        authenticator.setLifeTime(properties.getSessionLifeTime());
        return authenticator;
    }

    public TicketGrantingServiceResponse resolveTicketGrantingRequest(TicketGrantingServiceRequest request) {
        String url = UriComponentsBuilder
                .newInstance()
                .host(properties.getAuthenticationServerName())
                .pathSegment("kdc", "granting")
                .scheme("http")
                .build()
                .toString();
        return restTemplate.postForObject(url, request, TicketGrantingServiceResponse.class);
    }

    public ClientServerExchangeResponse resolveClientServerRequest(ClientServerExchangeRequest request) {
        String server = request.getServerName();
        UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(server);
        String url = UriComponentsBuilder
                .newInstance()
                .host(userDetails.getHost())
                .pathSegment("server", "auth")
                .scheme("http")
                .build()
                .toString();
        return restTemplate.postForObject(url, request, ClientServerExchangeResponse.class);
    }

    public String resolveServerTGT(String server) {
        UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(server);
        String url = UriComponentsBuilder
                .newInstance()
                .host(userDetails.getHost())
                .pathSegment("server", "tgt")
                .scheme("http")
                .build()
                .toString();
        return restTemplate.getForObject(url, String.class);
    }
}
