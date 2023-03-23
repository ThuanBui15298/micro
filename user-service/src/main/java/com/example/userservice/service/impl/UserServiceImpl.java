package com.example.userservice.service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.userservice.dto.UserDTO;
import com.example.userservice.entity.Position;
import com.example.userservice.entity.UserApp;
import com.example.userservice.repository.PositionRepository;
import com.example.userservice.repository.UserRepository;
import com.example.userservice.service.UserService;
import com.example.userservice.utils.Constants;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.validator.internal.engine.messageinterpolation.parser.MessageDescriptorFormatException;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class UserServiceImpl implements UserService {

    @Autowired
    private  UserRepository userRepository;

    @Autowired
    private  PositionRepository positionRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private Environment environment;

    @Autowired
    private HttpServletRequest request;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Transactional
    @Override
    public UserApp createUser(UserDTO userDTO) {
        Optional<Position> positionOptional = positionRepository.findById(userDTO.getPositionId());
        if (positionOptional.isEmpty()) {
            throw new MessageDescriptorFormatException("Position id can not found!");
        }
        Optional<UserApp> userOptional = userRepository.findByCodeAndDeleted(userDTO.getCode(), Constants.DONT_DELETE);
        if (userOptional.isPresent()) {
            throw new MessageDescriptorFormatException("Mã người dùng đã tồn tại");
        }

        UserApp userApp = new UserApp();
        BeanUtils.copyProperties(userDTO, userApp);
//        userApp.setPassword(Constants.PASSWORD);
        userApp.setCreatTime(new Date());
        userApp.setDeleted(Constants.DONT_DELETE);
        userApp.setStatus(Constants.STATUS_ACTIVE);
        userApp.setUpdateTime(new Date());
        userRepository.save(userApp);
        return userApp;
    }

    @Transactional
    @Override
    public UserApp updateUser(UserDTO userDTO, Long id) {

        Optional<Position> positionOptional = positionRepository.findById(userDTO.getPositionId());
        if (positionOptional.isEmpty()) {
            throw new MessageDescriptorFormatException(" Position id can not found!");
        }

        Optional<UserApp> userOptional = userRepository.findById(id);
        if (userOptional.isEmpty()) {
            throw new MessageDescriptorFormatException("Người dùng không tồn tại");
        }

        UserApp userApp = userOptional.get();
        BeanUtils.copyProperties(userDTO, userApp);
        userApp.setDeleted(Constants.DONT_DELETE);
        userApp.setStatus(Constants.STATUS_ACTIVE);
        userApp.setUpdateTime(new Date());
        userRepository.save(userApp);
        return userApp;
    }

    @Override
    public void deleteUser(List<Long> id) {
        List<UserApp> userAppList = userRepository.findByIdInAndDeleted(id, Constants.DONT_DELETE);
        if (CollectionUtils.isEmpty(userAppList)) {
            throw new MessageDescriptorFormatException(" Book id can not found!");
        }
        for (UserApp userApp : userAppList) {
            userApp.setDeleted(Constants.DELETED);
            userApp.setUpdateTime(new Date());
            userRepository.save(userApp);
        }
    }

    @Override
    public List<UserApp> getAllUser() {
        return userRepository.findAll();
    }

    @Override
    public UserApp getDetail(Long id) {
        Optional<UserApp> userOptional = userRepository.findById(id);
        if (userOptional.isEmpty()) {
            throw new MessageDescriptorFormatException(" UserApp id can not found!");
        }
        return userRepository.findAllById(id);
    }

    @Override
    public Map<String, Object> signIn(final String username, final String password) {
        UserApp userApp = userRepository.findByUserName(username);
        if (userApp == null) {
            throw new IllegalArgumentException("User does not exist in the system!");
        }
        try {
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(username, password);
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            User user = (User) authentication.getPrincipal();
            Algorithm algorithm = Algorithm.HMAC256(Objects.requireNonNull(environment.getProperty("jwt.secret")).getBytes());

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String access_token = JWT.create()
                    .withSubject(username)
                    .withIssuer(request.getRequestURL().toString())
                    .withExpiresAt(new Date(System.currentTimeMillis() +
                            Integer.parseInt(Objects.requireNonNull(environment.getProperty("jwt.access.token.expire")))))
                    .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList()))
                    .sign(algorithm);
            log.info("User {} login success", username);
            Map<String, Object> mapData = new HashMap<>();
            mapData.put("access_token", access_token);
            mapData.put("roles",
                    user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
            return mapData;
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new IllegalArgumentException("Username or password incorrect!");
        }
    }
}
