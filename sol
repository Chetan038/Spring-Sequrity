  "message": "The signing key's size is 152 bits which is not secure enough for the HS256 algorithm.  The JWT JWA Specification (RFC 7518, Section 3.2) states that keys used with HS256 MUST have a size >= 256 bits (the key size must be greater than or equal to the hash output size).  Consider using the io.jsonwebtoken.security.Keys class's 'secretKeyFor(SignatureAlgorithm.HS256)' method to create a key guaranteed to be secure enough for HS256.  See https://tools.ietf.org/html/rfc7518#section-3.2 for more information.",
    "path": "/api/login"

qWerTy4%iOpAsDfG7!hJkLzXcVbNm9&
// 1. First, let's create a JwtUtil class in the config package to handle token operations

package com.bostmytools.emppmng.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    // This should be a secure secret key - in production, store in environment variables
    private final String SECRET_KEY = "your_secure_jwt_secret_key_should_be_long_and_complex";
    
    // Token validity duration (in milliseconds) - 1 hour
    private final long JWT_TOKEN_VALIDITY = 1000 * 60 * 60;

    // Extract username from token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Extract expiration date from token
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Extract any claim from token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    
    // Parse the token and extract all claims
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    // Check if token is expired
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Generate token for user
    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    // Create token with claims and subject (username)
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    // Validate token
    public Boolean validateToken(String token, String username) {
        final String extractedUsername = extractUsername(token);
        return (extractedUsername.equals(username) && !isTokenExpired(token));
    }
}

// 2. Now, let's create a JwtInterceptor in the config package

package com.bostmytools.emppmng.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import com.bostmytools.emppmng.models.User;
import com.bostmytools.emppmng.services.UserService;

import java.util.Optional;

@Component
public class JwtInterceptor implements HandlerInterceptor {

    @Autowired
    private JwtUtil jwtUtil;
    
    @Autowired
    private UserService userService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // Skip authentication for login endpoint
        if (request.getRequestURI().contains("/api/login")) {
            return true;
        }
        
        // Get authorization header
        String authHeader = request.getHeader("Authorization");
        
        // Check if header exists and has correct format
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            // Extract token from header
            String token = authHeader.substring(7);
            
            try {
                // Extract username from token
                String username = jwtUtil.extractUsername(token);
                
                // Check if username exists
                if (username != null) {
                    // Get user from database by email (username)
                    Optional<User> userOpt = userService.findByEmail(username);
                    
                    // Validate token against user in database
                    if (userOpt.isPresent() && jwtUtil.validateToken(token, username)) {
                        // Set user in request attribute for later use if needed
                        request.setAttribute("user", userOpt.get());
                        return true;
                    }
                }
            } catch (Exception e) {
                // Token is invalid
            }
        }
        
        // Authentication failed
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("Unauthorized: Invalid or missing token");
        return false;
    }
}

// 3. Let's create a WebConfig class to register our interceptor

package com.bostmytools.emppmng.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private JwtInterceptor jwtInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // Apply interceptor to all endpoints under /api/ except login
        registry.addInterceptor(jwtInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/login");
    }
}

// 4. Let's modify the UserService interface to add the method to find users by email

package com.bostmytools.emppmng.services;

import java.util.Optional;

import com.bostmytools.emppmng.models.User;

public interface UserService {
    
    public Optional<User> authenticate(String email, String password);
    
    public Optional<User> findByEmail(String email);
}

// 5. Let's update the UserServiceImpl to implement the new method

package com.bostmytools.emppmng.services;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.bostmytools.emppmng.models.User;
import com.bostmytools.emppmng.repo.UserRepository;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;
    
    @Override
    public Optional<User> authenticate(String email, String password) {
        return userRepository.findByEmailAndPassword(email, password);
    }
    
    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}

// 6. Let's update the UserController to return JWT token on successful login

package com.bostmytools.emppmng.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bostmytools.emppmng.config.JwtUtil;
import com.bostmytools.emppmng.models.User;
import com.bostmytools.emppmng.services.UserService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private UserService userService;
    
    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials) {
        String email = credentials.get("email");
        String password = credentials.get("password");
        
        User user = userService.authenticate(email, password).orElse(null);
        
        if (user != null) {
            // Generate JWT token
            String token = jwtUtil.generateToken(user.getEmail());
            
            // Create response with token and user details (excluding password)
            Map<String, Object> response = new HashMap<>();
            response.put("token", token);
            response.put("user", Map.of(
                "id", user.getId(),
                "name", user.getName(),
                "email", user.getEmail(),
                "phoneNo", user.getPhoneNo()
            ));
            
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials"));
        }
    }
    
    // Add a test endpoint to verify JWT authentication
    @GetMapping("/test-auth")
    public ResponseEntity<?> testAuth() {
        return ResponseEntity.ok(Map.of("message", "You are authenticated!"));
    }
}

// 7. Finally, disable the default Spring Security configuration

package com.bostmytools.emppmng.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Disable default security since we're using our custom JWT interceptor
        http
            .csrf().disable()
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().permitAll()
            );
        
        return http.build();
    }
}




I'll create a JWT authentication system for your Spring Boot application using interceptors. Let's implement this step by step.
JWT Authentication ImplementationClick to open codeTap to open
File Structure and Where to Store Files
Place each file in the appropriate package based on its type:

Config Package (com.bostmystools.emppmng.config):

JwtUtil.java
JwtInterceptor.java
WebConfig.java
SecurityConfig.java


Update existing files:

UserService.java (in services package)
UserServiceImpl.java (in services package)
UserController.java (in controllers package)



Code Explanation and Flow
JWT Authentication Flow

User Login:

User sends login request with email and password to /api/login
UserController calls UserService to authenticate credentials
If valid, JwtUtil generates a JWT token
The token and user details are returned to the client


Protected API Calls:

For subsequent requests, the client includes the JWT token in the Authorization header
JwtInterceptor intercepts every request to /api/** (except /api/login)
The interceptor validates the token using JwtUtil
If valid, the request is allowed to proceed; otherwise, a 401 Unauthorized response is returned



Key Components Explained

JwtUtil:

Handles token generation, validation, and parsing
Uses the JJWT library to work with JWT tokens
Stores claims (data) in the token, including username and expiration


JwtInterceptor:

Implements Spring's HandlerInterceptor to intercept requests
Checks for the JWT token in the Authorization header
Validates the token and extracts user information


WebConfig:

Registers the interceptor and defines which paths it should be applied to


SecurityConfig:

Disables Spring Security's default authentication mechanism
Allows us to use our custom JWT authentication


UserService/UserServiceImpl:

Added a method to find users by email for token validation


UserController:

Updated to return a JWT token upon successful login
Added a test endpoint to verify authentication



Testing with Postman
1. Login and Get Token

Create a new POST request to http://localhost:8080/api/login
Set the request body to JSON format with:
jsonCopy{
    "email": "your_email@example.com",
    "password": "your_password"
}

Send the request - you should receive a response with:
jsonCopy{
    "token": "eyJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": 1,
        "name": "User Name",
        "email": "your_email@example.com",
        "phoneNo": "1234567890"
    }
}

Copy the token value

2. Access Protected Endpoints

Create a new GET request to http://localhost:8080/api/test-auth or any other protected endpoint
Add an Authorization header:

Key: Authorization
Value: Bearer eyJhbGciOiJIUzI1NiJ9... (the token you received)


Send the request - you should receive the response from the protected endpoint
If you remove or modify the token, you should get a 401 Unauthorized response

3. Try Employee Endpoints
You can also test the employee endpoints like:

GET http://localhost:8080/api/employees/all
GET http://localhost:8080/api/employees/byid/{empId}
POST http://localhost:8080/api/employees/create
PUT http://localhost:8080/api/employees/edit/{empId}
DELETE http://localhost:8080/api/employees/delete/{empId}

Remember to always include the Authorization header with your JWT token.
Additional Notes and Best Practices

Security Considerations:

In a production environment, store the JWT secret key in environment variables or a secure configuration
Consider encrypting sensitive data in the database, especially passwords
Use HTTPS for all API communications


Token Management:

The current implementation sets token expiration to 1 hour
You might want to implement refresh tokens for longer sessions
Consider adding a logout mechanism (server-side token invalidation)


Error Handling:

Implement more detailed error responses for different authentication failures
Add proper exception handling throughout the authentication flow



By following this implementation, you'll have a secure JWT-based authentication system integrated with your existing Spring Boot application.
