package net.yan.kerberos.client;

import net.yan.kerberos.config.ClientSettings;
import net.yan.kerberos.data.AuthenticationServiceRequest;

import java.time.Instant;

public class AuthenticationServiceRequestBuilder {

    private String username;

    private String address;

    private ClientSettings clientSettings;

    public String getUsername() {
        return username;
    }

    public AuthenticationServiceRequestBuilder setUsername(String username) {
        this.username = username;
        return this;
    }

    public String getAddress() {
        return address;
    }

    public AuthenticationServiceRequestBuilder setAddress(String address) {
        this.address = address;
        return this;
    }

    public ClientSettings getClientSettings() {
        return clientSettings;
    }

    public void setClientSettings(ClientSettings clientSettings) {
        this.clientSettings = clientSettings;
    }

    public AuthenticationServiceRequest build() {
        AuthenticationServiceRequest request = new AuthenticationServiceRequest();
        request.setLifeTime(getClientSettings().getSessionLifeTime());
        request.setStartTime(Instant.now().toEpochMilli());
        request.setAddress(getAddress());
        request.setUsername(getUsername());
        return request;
    }
}
