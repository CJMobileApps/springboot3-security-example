package com.cjmobileapps.security.user

import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository: JpaRepository<User, Int> {

    fun findByEmail(email: String): User?
}
