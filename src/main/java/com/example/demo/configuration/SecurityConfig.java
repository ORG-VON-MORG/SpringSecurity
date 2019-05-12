package com.example.demo.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;

import java.util.Arrays;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  /*
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers("/user/**").hasRole("USER")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin().loginPage("/login").defaultSuccessUrl("/index.html")
                .permitAll();



       // http.authorizeRequests().anyRequest().authenticated().and().httpBasic();


    }
    */

    /*
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        auth
                .inMemoryAuthentication()
                //.withUser("user").password("password").roles("USER");
                .withUser("user").password(passwordEncoder().encode("password")).roles("USER");
    }

    */

    @Bean
    public static PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
/*
    @Bean
    public ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider() {
        ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider = new
                ActiveDirectoryLdapAuthenticationProvider("gps-srp.local", "ldap://192.168.178.98:389/");
        return activeDirectoryLdapAuthenticationProvider;
    }

*/


//-----------Von der Webseite https://stackoverflow.com/questions/42229066/spring-boot-ldap-securityhttps://stackoverflow.com/questions/42229066/spring-boot-ldap-security
/*
    @Override
    protected void configure(AuthenticationManagerBuilder authManagerBuilder) throws Exception {
        authManagerBuilder.authenticationProvider(activeDirectoryLdapAuthenticationProvider()).userDetailsService(userDetailsService());
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(Arrays.asList(activeDirectoryLdapAuthenticationProvider()));
    }
    @Bean
    public AuthenticationProvider activeDirectoryLdapAuthenticationProvider() {
        ActiveDirectoryLdapAuthenticationProvider provider = new ActiveDirectoryLdapAuthenticationProvider("gps-srp.local", "ldap://192.168.178.98:389/", "dc=gps-srp,dc=local");
        provider.setSearchFilter("(&(objectClass=user)(sAMAccountName={0}))");
        provider.setConvertSubErrorCodesToExceptions(true);
        provider.setUseAuthenticationRequestCredentials(true);
        return provider;
    }
    */

//-------------------------------------------

//-------------------https://www.ziaconsulting.com/developer-help/spring-security-active-directory/
@Override
protected void configure(HttpSecurity http) throws Exception
{
    http
            .authorizeRequests()
            .anyRequest().fullyAuthenticated()
            .httpBasic();
}

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception
    {
        ActiveDirectoryLdapAuthenticationProvider adProvider =
                new ActiveDirectoryLdapAuthenticationProvider(domain,url);
        adProvider.setConvertSubErrorCodesToExceptions(true);
        adProvider.setUseAuthenticationRequestCredentials(true);

        // set pattern if it exists
        // The following example would authenticate a user if they were a member
        // of the ServiceAccounts group
        // (&(objectClass=user)(userPrincipalName={0})
        //   (memberof=CN=ServiceAccounts,OU=alfresco,DC=mycompany,DC=com))
        if (userDNPattern != null && userDNPattern.trim().length() > 0)
        {
            adProvider.setSearchFilter(userDNPattern);
        }
        auth.authenticationProvider(adProvider);

        // don't erase credentials if you plan to get them later
        // (e.g using them for another web service call)
        auth.eraseCredentials(false);
    }
//----------------------------------------------












}