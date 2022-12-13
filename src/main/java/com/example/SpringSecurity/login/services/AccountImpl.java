package com.example.SpringSecurity.login.services;

import java.util.List;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.SpringSecurity.login.model.AppRole;
import com.example.SpringSecurity.login.model.AppUser;

import lombok.AllArgsConstructor;

import com.example.SpringSecurity.login.Repository.AppRoleRepository;
import com.example.SpringSecurity.login.Repository.AppUserRepo;

@Service
public class AccountImpl implements Account {

    private AppUserRepo appUserRepository;
    private AppRoleRepository appRoleRepository;
    private PasswordEncoder passwordEncoder;

    public AccountImpl(AppUserRepo appUserRepository, AppRoleRepository appRoleRepository, PasswordEncoder passwordEncoder) {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
        this.passwordEncoder = passwordEncoder;
    }
 

    @Override
    public AppUser saveUser(String username, String password, String confirmedPassword) {
        AppUser user=appUserRepository.findByUsername(username);
        if(user!=null) throw new RuntimeException("User already exists");
        if(!password.equals(confirmedPassword)) throw new RuntimeException("Please confirm your password");
        AppUser appUser=new AppUser();
        appUser.setUsername(username);
        appUser.setActived(true);
        appUser.setPassword(passwordEncoder.encode(password));
        appUserRepository.save(appUser);
        addRoleToUser(username,"USER");
        addRoleToUser(username,"ADMIN");
        return appUser;
    }

    @Override
    public List<AppUser> list(){
        return appUserRepository.findAll();
    }

    @Override
    public AppRole save(AppRole role) {
        return appRoleRepository.save(role);
    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepository.findByUsername(username);
    }

    @Override
    public void addRoleToUser(String username, String rolename) {
        AppUser appUser=appUserRepository.findByUsername(username);
        AppRole appRole=appRoleRepository.findByRoleName(rolename);
        appUser.getRoles().add(appRole);
    }

}
