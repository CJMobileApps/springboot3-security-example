package com.cjmobileapps.security.config

import io.jsonwebtoken.JwtException
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.jwt.BadJwtException
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter


// https://github.com/spring-projects/spring-security/blob/main/oauth2/oauth2-resource-server/src/main/java/org/springframework/security/oauth2/server/resource/authentication/JwtAuthenticationProvider.java
//TODO this doesnt even get used what's the point?
@Configuration
class JwtAuthenticationProvider(
    val jwtService: JwtService
) : AuthenticationProvider {
//    private val logger: Log = LogFactory.getLog(javaClass)
//    private val jwtDecoder: JwtDecoder
//    private var jwtAuthenticationConverter: Converter<Jwt, out AbstractAuthenticationToken> =
//        JwtAuthenticationConverter()
//
//    init {
//        Assert.notNull(jwtDecoder, "jwtDecoder cannot be null")
//        this.jwtDecoder = jwtDecoder
//    }

    init {
        println("HERE_ is JwtAuthenticationProvider called")
    }

    private val jwtAuthenticationConverter: Converter<Jwt, out AbstractAuthenticationToken?> =
        JwtAuthenticationConverter()

    /**
     * Decode and validate the
     * [Bearer
 * Token](https://tools.ietf.org/html/rfc6750#section-1.2).
     * @param authentication the authentication request object.
     * @return A successful authentication
     * @throws AuthenticationException if authentication failed for some reason
     */

    @Bean
    fun jwtDecoder(): JwtDecoder {
        println("HERE_ jwtDecoder()")
        return JwtDecoder { token ->
            println("BLAH token: $token")
            if(!jwtService.isTokenValid(token)) throw Exception("hfhf");

            val blah = Jwt
                .withTokenValue(token)
                .build()

            println("BLAH " + blah)
            blah
        }
    }

    override fun authenticate(authentication: Authentication): Authentication {
        val bearerToken: BearerTokenAuthenticationToken  = authentication as BearerTokenAuthenticationToken
        val jwt = getJwt(bearerToken)
        val token = this.jwtAuthenticationConverter.convert(jwt!!)
        if(token?.details == null) {
            token?.details = bearerToken.details
        }
        println("Authenticaed token")
        return token!!
    }

    private fun getJwt(bearer: BearerTokenAuthenticationToken): Jwt? {
        return try {
            jwtDecoder().decode(bearer.token)
        } catch (failed: BadJwtException) {
            println("Failed to authenticate since the JWT was invalid")
            println()
            throw InvalidBearerTokenException(failed.message, failed)
        } catch (failed: JwtException) {
            throw AuthenticationServiceException(failed.message, failed)
        }
    }

    override fun supports(authentication: Class<*>): Boolean {
        return BearerTokenAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

//    @Throws(AuthenticationException::class)
//    override fun authenticate(authentication: Authentication): Authentication {
//        val bearer: BearerTokenAuthenticationToken = authentication as BearerTokenAuthenticationToken
//        val jwt: Jwt = getJwt(bearer)
//        val token: AbstractAuthenticationToken = jwtAuthenticationConverter.convert(jwt)
//        if (token.details == null) {
//            token.details = bearer.getDetails()
//        }
//        logger.debug("Authenticated token")
//        return token
//    }
//
//    private fun getJwt(bearer: BearerTokenAuthenticationToken): Jwt {
//        return try {
//            jwtDecoder.decode(bearer.getToken())
//        } catch (failed: BadJwtException) {
//            logger.debug("Failed to authenticate since the JWT was invalid")
//            throw InvalidBearerTokenException(failed.getMessage(), failed)
//        } catch (failed: JwtException) {
//            throw AuthenticationServiceException(failed.message, failed)
//        }
//    }
//
//    override fun supports(authentication: Class<*>?): Boolean {
//        return BearerTokenAuthenticationToken::class.java.isAssignableFrom(authentication)
//    }
//
//    fun setJwtAuthenticationConverter(
//        jwtAuthenticationConverter: Converter<Jwt?, out AbstractAuthenticationToken?>
//    ) {
//        Assert.notNull(jwtAuthenticationConverter, "jwtAuthenticationConverter cannot be null")
//        this.jwtAuthenticationConverter = jwtAuthenticationConverter
//    }
}