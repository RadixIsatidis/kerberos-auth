package net.yan.kerberos.examples.kdc;

import net.yan.kerberos.kdc.as.AuthenticationService;
import net.yan.kerberos.kdc.userdetails.UserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @author yanle
 */
@Service
public class KDCService {

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private UserDetailsService userDetailsService;



}
