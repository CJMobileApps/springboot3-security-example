package com.cjmobileapps.security.auth

import com.cjmobileapps.security.config.JwtService
import com.cjmobileapps.security.user.Role
import com.cjmobileapps.security.user.User
import com.cjmobileapps.security.user.UserRepository
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class AuthenticationService(
    val repository: UserRepository,
    val passwordEncoder: PasswordEncoder,
    val jwtService: JwtService,
    val authenticationManager: AuthenticationManager
) {

    fun register(request: RegisterRequest): AuthenticationResponse {
        val user = User(
            firstname = request.firstname,
            lastname = request.lastname,
            email = request.email,
            passwordString = passwordEncoder.encode(request.password),
            role = Role.USER
        )
        repository.save(user)
        val jwtToken = jwtService.generateToken(user)
        return AuthenticationResponse(token = jwtToken)
    }

    fun authenticate(request: AuthenticationRequest): AuthenticationResponse {
        authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(
                request.email,
                request.password
            )
        )
        val user = repository.findByEmail(request.email)
        val jwtToken = jwtService.generateToken(user!!)
        return AuthenticationResponse(token = jwtToken)
    }
}
