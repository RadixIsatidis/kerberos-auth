package net.yan.kerberos.examples.userdetails;

import net.yan.kerberos.kdc.userdetails.UserDetails;
import net.yan.kerberos.kdc.userdetails.UserDetailsService;
import net.yan.kerberos.kdc.userdetails.UsernameNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @author yanle
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserDetailsRepository userDetailsRepository;

    @Autowired
    public UserDetailsServiceImpl(UserDetailsRepository userDetailsRepository) {
        this.userDetailsRepository = userDetailsRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userDetailsRepository.findOne(username);
    }
}
