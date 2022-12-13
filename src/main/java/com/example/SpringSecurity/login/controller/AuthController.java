package com.example.SpringSecurity.login.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import java.util.stream.Collectors;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.SpringSecurity.login.model.AppRole;
import com.example.SpringSecurity.login.model.AppUser;
import com.example.SpringSecurity.login.services.Account;
import com.nimbusds.jwt.JWT;

import lombok.Data;


@RestController
public class AuthController {

    
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;
    private AuthenticationManager authenticationManager;
    private UserDetailsService userDetailsService;
    private Account accountService;
    private PasswordEncoder passwordEncoder;

    public AuthController(Account accountService, PasswordEncoder passwordEncoder, JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, AuthenticationManager authenticationManager){
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.accountService = accountService;
    }

    // @PostMapping("/register")
    // public AppUser register(@RequestBody  UserForm userForm){
    //     return  accountService.saveUser(
    //             userForm.getUsername(),userForm.getPassword(),userForm.getConfirmedPassword());
    // }

    @PostMapping("/token")
    public Map<String, String> jwtToken(String grantType, String username, String password, Boolean withRefreshToken, String refreshToken){

        String scope=null;
        String subject=null;

        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password)
        );
        subject = authentication.getName();
        scope = authentication.getAuthorities().stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));
        // scope = "ADMIN";
        System.out.println(scope);
        // if(grantType == "password")
        // {
            
        //     Authentication authentication = authenticationManager.authenticate(
        //         new UsernamePasswordAuthenticationToken(username, password)
        //     );
        //     subject = authentication.getName();
        //     scope = authentication.getAuthorities().stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));
        // } 
        
        // else if(grantType == "refreshToken"){
        //     Jwt decodeJwt = jwtDecoder.decode(refreshToken);
        //     subject = decodeJwt.getSubject();
        //     UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
        //     Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();

        //     scope = authorities.stream().map(auth -> auth.getAuthority()).collect(Collectors.joining(" "));

        // }
        
        Map<String, String> idToken = new HashMap<>();

        Instant instant = Instant.now();

        // scope = authentication.getAuthorities().stream().map(aut -> aut.getAuthority()).collect(Collectors.joining(" "));

        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
        .subject(subject)
        .issuedAt(instant)
        .expiresAt(instant.plus(withRefreshToken?5:10, ChronoUnit.MINUTES))
        .issuer("spring-security")
        .claim("scope", scope)
        .build();

        String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();

        idToken.put("accessToken", jwtAccessToken);
        if(withRefreshToken){

            JwtClaimsSet jwtClaimsSetRefresh = JwtClaimsSet.builder()
            .subject(subject)
            .issuedAt(instant)
            .expiresAt(instant.plus(60, ChronoUnit.MINUTES))
            .issuer("spring-security")
            .claim("scope", scope)
            .build();

            String jwtRefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();

            idToken.put("refreshToken", jwtRefreshToken);

        }

        return idToken;
    }

    @PostMapping("/saveUser")
    public AppUser savUser(@RequestBody UserForm userForm){

        return accountService.saveUser(userForm.getUsername(),userForm.getPassword(), userForm.getConfirmedPassword());
    }
    @PostMapping("/saveRole")
    public AppRole saveRole(@RequestBody AppRole appRole){

        return accountService.save(appRole);
    }

    @PostMapping("/addRole")
    public void addRole(@RequestBody String username, @RequestBody String roleName){

        accountService.addRoleToUser(username, roleName);
    }

    
}

@Data
class UserForm{
    private String username;
    private String password;
    private String confirmedPassword;
}
