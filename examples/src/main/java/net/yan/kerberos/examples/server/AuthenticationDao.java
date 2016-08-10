package net.yan.kerberos.examples.server;

import net.yan.kerberos.data.AuthenticationServiceRequest;
import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.ClientServerExchangeResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Repository;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;

/**
 * @author yanle
 */
@Repository
public class AuthenticationDao {

    @Autowired
    private ServerProperties properties;

    @Autowired
    private RestTemplate restTemplate;

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

//    public void resolveClientServerExchange(ClientServerExchangeResponse response) {
//        String client = response.getClient();
//        String url = UriComponentsBuilder
//                .newInstance()
//                .host(client)
//                .pathSegment("client", "auth")
//                .scheme("http")
//                .build()
//                .toString();
//        ResponseEntity<Void> responseEntity = restTemplate.postForEntity(url, response, Void.class);
//        if (!responseEntity.getStatusCode().is2xxSuccessful()) {
//            throw new RuntimeException("Response error: " + responseEntity);
//        }
//    }
}
