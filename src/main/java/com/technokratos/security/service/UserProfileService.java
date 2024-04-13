package com.technokratos.security.service;

import com.technokratos.security.repository.UserProfileRepositoryMock;
import com.technokratos.security.security.userdetails.UserProfile;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserProfileService {

    private final UserProfileRepositoryMock userRepositoryMock;

    public UserProfile getUserByLogin(String login) {
        return userRepositoryMock.findByLogin(login);
    }
}