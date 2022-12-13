package com.example.SpringSecurity.login.config;

import com.example.SpringSecurity.login.Repository.AppUserRepo;
import com.example.SpringSecurity.login.model.AppUser;
import com.example.SpringSecurity.login.services.Account;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private RsaKeysConfig rsaKeysConfig;
    private PasswordEncoder passwordEncoder;
    private Account accountService;
    private AppUserRepo appUserRepo;

    public SecurityConfig(AppUserRepo appUserRepo, Account accountService, RsaKeysConfig rsakeysConfig, PasswordEncoder passwordEncoder) {
        this.rsaKeysConfig = rsakeysConfig;
        this.passwordEncoder = passwordEncoder;
        this.accountService = accountService;
        this.appUserRepo = appUserRepo;
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService){
        DaoAuthenticationProvider autProvider = new DaoAuthenticationProvider();

        autProvider.setPasswordEncoder(passwordEncoder);
        autProvider.setUserDetailsService(userDetailsService);

        return new ProviderManager(autProvider);

    }


    @Bean
    public UserDetailsService userDetailsService(){
        // return new InMemoryUserDetailsManager(
        //     User.withUsername("user").password(passwordEncoder.encode("123")).authorities("USER").build(),
        //     User.withUsername("user1").password(passwordEncoder.encode("123")).authorities("USER").build(),
        //     User.withUsername("admin").password(passwordEncoder.encode("123")).authorities("USER","ADMIN").build()
        // );

        return new UserDetailsService() {

            public UserDetails loadUserByUsername(String username){
                AppUser appUser=accountService.loadUserByUsername(username);
                if(appUser==null) throw new UsernameNotFoundException("invalid user");
                Collection<GrantedAuthority> authorities=new ArrayList<>();
                appUser.getRoles().forEach(r->{
                    authorities.add(new SimpleGrantedAuthority(r.getRoleName()));
                });
                return new User(appUser.getUsername(),appUser.getPassword(),authorities);
            }
        };
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
            .csrf(csrf -> csrf.disable())
            .authorizeRequests(auth -> auth.antMatchers("/token").permitAll())
            .authorizeRequests(auth -> auth.antMatchers("/saveUser").permitAll())
            .authorizeRequests(auth -> auth.antMatchers("/saveRole").permitAll())
            .authorizeRequests(auth -> auth.anyRequest().authenticated())
            .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
            .build();
    }

    @Bean
    JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(rsaKeysConfig.publicKey()).build();
    }

    @Bean
    JwtEncoder jwtEncoder(){
        JWK jwk= new RSAKey.Builder(rsaKeysConfig.publicKey()).privateKey(rsaKeysConfig.privateKey()).build();
        JWKSource<SecurityContext> jwkSource= new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }
}
