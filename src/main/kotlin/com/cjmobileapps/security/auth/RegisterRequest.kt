package com.cjmobileapps.security.auth

import com.cjmobileapps.security.user.Role

data class RegisterRequest(
    val firstname: String,
    val lastname: String,
    val email: String,
    val password: String,
    val role: Role,
)
