package net.yan.kerberos.examples.userdetails;

import net.yan.kerberos.examples.AppConfiguration;
import net.yan.kerberos.kdc.userdetails.UserDetails;
import net.yan.kerberos.kdc.userdetails.UserDetailsService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * @author yanle
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = {
        AppConfiguration.class
})
@EnableTransactionManagement
@Transactional
public class UserDetailsServiceImplTest {

    @Autowired
    private UserDetailsService userDetailsService;

    @Test
    public void loadUserByUsername() throws Exception {
        UserDetails userDetails = userDetailsService.loadUserByUsername("kdc");
        assertNotNull(userDetails);
        assertEquals("kdc", userDetails.getUsername());
    }

}