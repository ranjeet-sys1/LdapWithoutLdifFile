/**
 *
 */
package com.app.controllers;

import com.app.Model.LoginRequest;
import com.app.util.JwtUtils;
import com.app.utility.ResponseConstantIntegerValue;
import com.app.utility.ResponseConstantValue;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@RestController
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtils jwtUtils;


	@PostMapping("/login")
    public ResponseEntity authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtUtils.generateToken(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority()).collect(Collectors.toList());
        Map<String, String> response = new HashMap<>();
        response.put("username", userDetails.getUsername());
        response.put("name",authentication.getName());
        response.put("token", token);
        response.put("roles", String.valueOf(roles));
        response.put("response value", ResponseConstantValue.SUCCESS_MESSAGE);
        response.put("response code", String.valueOf(ResponseConstantIntegerValue.SUCCESS_RESPONSE));
        return new ResponseEntity(response, HttpStatus.OK);
    }
}
