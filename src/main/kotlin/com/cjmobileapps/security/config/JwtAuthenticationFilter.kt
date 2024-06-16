package com.cjmobileapps.security.config

import com.cjmobileapps.security.auth.AuthenticationService
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthenticationFilter(
    val jwtService: JwtService,
//    val userDetailsService: UserDetailsService
    val authenticationService: AuthenticationService
) : OncePerRequestFilter() {


    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val authHeader = request.getHeader("Authorization")
        var jwt = ""
        var userEmail = ""
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response)
            return
        }

        jwt = authHeader.substring(7)
        userEmail = jwtService.extractUsername(jwt)
        println("HERE_ userEmail " + userEmail)
        println("HERE_ SecurityContextHolder.getContext().authentication " + SecurityContextHolder.getContext().authentication)
        if (userEmail != null && SecurityContextHolder.getContext().authentication == null) {
            //val userDetails = this.userDetailsService.loadUserByUsername(userEmail)
            val userDetails = com.cjmobileapps.security.user.User()
            //if (jwtService.isTokenValid(jwt, userDetails)) {
                val authToken = UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.authorities
                )
                authToken.details = WebAuthenticationDetailsSource().buildDetails(request)
                SecurityContextHolder.getContext().authentication = authToken
           // }
        }
        filterChain.doFilter(request, response)
    }
}