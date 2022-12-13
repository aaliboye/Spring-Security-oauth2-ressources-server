package com.example.SpringSecurity.login.services;

import java.util.List;

import com.example.SpringSecurity.login.model.AppRole;
import com.example.SpringSecurity.login.model.AppUser;



public interface Account {
    public AppUser saveUser(String username,String password,String confirmedPassword);
    public AppRole save(AppRole role);
    public List<AppUser> list();
    public AppUser loadUserByUsername(String username);
    public void addRoleToUser(String username,String rolename);
}
