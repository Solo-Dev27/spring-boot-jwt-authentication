# 🔐 Spring Boot JWT Authentication

![Java](https://img.shields.io/badge/Java-17-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.2-6DB33F?style=for-the-badge&logo=spring-boot&logoColor=white)
![Spring Security](https://img.shields.io/badge/Spring_Security-6DB33F?style=for-the-badge&logo=spring-security&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-black?style=for-the-badge&logo=JSON%20web%20tokens)

> Complete JWT authentication system with Spring Security, role-based access control (RBAC), and refresh tokens.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Authentication Flow](#-authentication-flow)
- [Getting Started](#-getting-started)
- [API Endpoints](#-api-endpoints)
- [Code Examples](#-code-examples)
- [Security Configuration](#-security-configuration)
- [Testing](#-testing)

---

## 🎯 Overview

This project demonstrates a production-ready JWT authentication system built with Spring Boot and Spring Security. It includes:
- User registration and login
- JWT token generation and validation
- Refresh token mechanism
- Role-based access control (RBAC)
- Password encryption
- Stateless authentication

Perfect for learning Spring Security or as a starting point for your authenticated applications.

---

## ✨ Features

- ✅ **JWT Authentication** - Stateless authentication with JSON Web Tokens
- ✅ **User Registration** - Secure user registration with validation
- ✅ **User Login** - Authentication with username/email and password
- ✅ **Access Tokens** - Short-lived JWT tokens for API access
- ✅ **Refresh Tokens** - Long-lived tokens for obtaining new access tokens
- ✅ **Role-Based Access Control (RBAC)** - Multiple roles (USER, ADMIN, MODERATOR)
- ✅ **Password Encryption** - BCrypt password hashing
- ✅ **Token Validation** - Comprehensive JWT validation
- ✅ **Method-Level Security** - `@PreAuthorize` annotations
- ✅ **Exception Handling** - Custom security exception handlers

---

## 🛠️ Tech Stack

- **Java 17** - Modern Java features
- **Spring Boot 3.2** - Application framework
- **Spring Security** - Authentication and authorization
- **Spring Data JPA** - Data persistence
- **PostgreSQL** - Relational database
- **JWT (jjwt)** - JWT token library
- **BCrypt** - Password hashing
- **Lombok** - Reduce boilerplate code
- **Maven** - Build automation

---

## 🔄 Authentication Flow

### **Registration Flow**
```
1. User submits registration form (username, email, password)
2. System validates input
3. System hashes password with BCrypt
4. System creates user with default USER role
5. System saves user to database
6. Returns success message
```

### **Login Flow**
```
1. User submits credentials (username/email, password)
2. System validates credentials
3. If valid, generate JWT access token (expires in 24 hours)
4. Generate refresh token (expires in 30 days)
5. Return tokens to client
6. Client stores tokens (localStorage/cookies)
```

### **API Request Flow**
```
1. Client sends request with JWT in Authorization header
2. JwtAuthenticationFilter intercepts request
3. Extract and validate JWT token
4. If valid, set authentication in SecurityContext
5. Proceed to controller
6. If invalid/expired, return 401 Unauthorized
```

### **Token Refresh Flow**
```
1. Access token expires
2. Client sends refresh token to /api/auth/refresh
3. System validates refresh token
4. If valid, generate new access token
5. Return new access token to client
```

---

## 🚀 Getting Started

### **Prerequisites**
- Java 17 or higher
- Maven 3.8+
- PostgreSQL 15+

### **Installation**

1. **Clone the repository**
```bash
git clone https://github.com/Solo-Dev27/spring-boot-jwt-authentication.git
cd spring-boot-jwt-authentication
```

2. **Configure Database**
```yaml
# application.yml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/jwt_auth_db
    username: your_username
    password: your_password
    
jwt:
  secret: your-256-bit-secret-key-here-make-it-long-and-random
  expiration: 86400000  # 24 hours in milliseconds
  refresh-expiration: 2592000000  # 30 days in milliseconds
```

3. **Build the project**
```bash
mvn clean install
```

4. **Run the application**
```bash
mvn spring-boot:run
```

5. **Access the API**
- API: http://localhost:8080
- H2 Console (if using H2 for testing): http://localhost:8080/h2-console

---

## 📚 API Endpoints

### **Authentication Endpoints**

| Method | Endpoint | Description | Request Body | Response | Auth Required |
|--------|----------|-------------|--------------|----------|---------------|
| POST | `/api/auth/register` | Register new user | `RegisterRequest` | `MessageResponse` | ❌ |
| POST | `/api/auth/login` | User login | `LoginRequest` | `JwtResponse` | ❌ |
| POST | `/api/auth/refresh` | Refresh access token | `RefreshTokenRequest` | `JwtResponse` | ❌ |
| POST | `/api/auth/logout` | User logout | - | `MessageResponse` | ✅ |

### **Protected Endpoints (Examples)**

| Method | Endpoint | Description | Required Role | Auth Required |
|--------|----------|-------------|---------------|---------------|
| GET | `/api/test/all` | Public content | - | ❌ |
| GET | `/api/test/user` | User content | USER | ✅ |
| GET | `/api/test/mod` | Moderator content | MODERATOR | ✅ |
| GET | `/api/test/admin` | Admin content | ADMIN | ✅ |

---

## 💻 Code Examples

### **1. User Entity**
```java
@Entity
@Table(name = "users",
       uniqueConstraints = {
           @UniqueConstraint(columnNames = "username"),
           @UniqueConstraint(columnNames = "email")
       })
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank
    @Size(max = 20)
    private String username;
    
    @NotBlank
    @Size(max = 50)
    @Email
    private String email;
    
    @NotBlank
    @Size(max = 120)
    private String password;
    
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles",
               joinColumns = @JoinColumn(name = "user_id"),
               inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();
    
    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }
}
```

### **2. Role Entity**
```java
@Entity
@Table(name = "roles")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Role {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private ERole name;
}

public enum ERole {
    ROLE_USER,
    ROLE_MODERATOR,
    ROLE_ADMIN
}
```

### **3. JWT Token Provider**
```java
@Component
public class JwtTokenProvider {
    
    @Value("${jwt.secret}")
    private String jwtSecret;
    
    @Value("${jwt.expiration}")
    private long jwtExpiration;
    
    public String generateToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
        
        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }
    
    public String getUsernameFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
    
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
```

### **4. JWT Authentication Filter**
```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    @Autowired
    private JwtTokenProvider tokenProvider;
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   FilterChain filterChain) 
            throws ServletException, IOException {
        
        try {
            String jwt = getJwtFromRequest(request);
            
            if (jwt != null && tokenProvider.validateToken(jwt)) {
                String username = tokenProvider.getUsernameFromToken(jwt);
                
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        userDetails, 
                        null, 
                        userDetails.getAuthorities()
                    );
                authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
                );
                
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```

### **5. Security Configuration**
```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;
    
    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .exceptionHandling(exception -> 
                exception.authenticationEntryPoint(unauthorizedHandler)
            )
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/test/all").permitAll()
                .anyRequest().authenticated()
            );
        
        http.addFilterBefore(jwtAuthenticationFilter, 
                            UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}
```

### **6. Authentication Controller**
```java
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            return ResponseEntity.badRequest()
                .body(new MessageResponse("Error: Username is already taken!"));
        }
        
        if (userRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity.badRequest()
                .body(new MessageResponse("Error: Email is already in use!"));
        }
        
        // Create new user
        User user = new User(
            request.getUsername(),
            request.getEmail(),
            passwordEncoder.encode(request.getPassword())
        );
        
        // Assign default role
        Set<String> strRoles = request.getRoles();
        Set<Role> roles = new HashSet<>();
        
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        
        user.setRoles(roles);
        userRepository.save(user);
        
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
    
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()
            )
        );
        
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.generateToken(authentication);
        
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
            .map(item -> item.getAuthority())
            .collect(Collectors.toList());
        
        return ResponseEntity.ok(new JwtResponse(
            jwt,
            userDetails.getId(),
            userDetails.getUsername(),
            userDetails.getEmail(),
            roles
        ));
    }
}
```

### **7. Protected Controller Example**
```java
@RestController
@RequestMapping("/api/test")
public class TestController {
    
    @GetMapping("/all")
    public String allAccess() {
        return "Public Content.";
    }
    
    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess() {
        return "User Content.";
    }
    
    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess() {
        return "Moderator Board.";
    }
    
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin Board.";
    }
}
```

---

## 🔒 Security Configuration

### **JWT Secret Key Generation**
```bash
# Generate a secure random key (256-bit)
openssl rand -base64 64
```

### **Token Expiration**
- **Access Token**: 24 hours (86400000 ms)
- **Refresh Token**: 30 days (2592000000 ms)

### **Password Requirements**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

---

## ✅ Testing

### **Manual Testing with Postman/cURL**

**1. Register User**
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "Test123!@#",
    "roles": ["user"]
  }'
```

**2. Login**
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "Test123!@#"
  }'
```

**3. Access Protected Endpoint**
```bash
curl -X GET http://localhost:8080/api/test/user \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

---

## 📄 License

This project is licensed under the MIT License.

---

## 👤 Author

**Solomon Ilegar**
- GitHub: [@Solo-Dev27](https://github.com/Solo-Dev27)
- LinkedIn: [Solomon Ilegar](https://www.linkedin.com/in/solomonilegar/)

---

**⭐ If you find this project helpful, please give it a star!**
