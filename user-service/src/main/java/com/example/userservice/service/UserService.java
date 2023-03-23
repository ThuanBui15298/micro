package com.example.userservice.service;

import com.example.userservice.dto.UserDTO;
import com.example.userservice.entity.UserApp;

import java.util.List;
import java.util.Map;

public interface UserService {

    UserApp createUser(UserDTO userDTO);

    UserApp updateUser(UserDTO userDTO, Long id);

    void deleteUser(List<Long> id);

    List<UserApp> getAllUser();

    UserApp getDetail(Long id);

    Map<String, Object> signIn(final String username, final String password);
}