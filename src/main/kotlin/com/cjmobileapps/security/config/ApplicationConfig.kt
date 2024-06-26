package com.cjmobileapps.security.config

import com.cjmobileapps.security.user.User
import com.cjmobileapps.security.user.UserRepository
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder


@Configuration
class ApplicationConfig(
    val repository: UserRepository
) {

//    @Bean
//    fun userDetailsService(): UserDetailsService {
//        return UserDetailsService { username: String ->
//
////            return@UserDetailsService repository.findByEmail(username) ?: throw UsernameNotFoundException("User not found")
//            return@UserDetailsService User(
//
//            )
//        }
//    }

//    @Bean
//    fun authenticationProvider(): AuthenticationProvider {
//        val authProvider = DaoAuthenticationProvider()
//        authProvider.setUserDetailsService(userDetailsService())
//        authProvider.setPasswordEncoder(passwordEncoder())
//        return authProvider
//    }

//    @Bean
//    fun authenticationManager(config: AuthenticationConfiguration): AuthenticationManager {
//        return config.authenticationManager
//    }
//
//    @Bean
//    fun passwordEncoder(): PasswordEncoder {
//        return BCryptPasswordEncoder()
//    }
}
