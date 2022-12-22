package by.home.securitytest.web;

import by.home.securitytest.model.AuthRequest;
import by.home.securitytest.model.RegistrationRequest;
import by.home.securitytest.model.User;
import by.home.securitytest.model.UserDto;
import by.home.securitytest.repository.UserRepository;
import by.home.securitytest.util.JwtUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthorizationController {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authManager;

    private final JwtUtils jwtUtils;

    public AuthorizationController(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager authManager, JwtUtils jwtUtils) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authManager = authManager;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/register")
    public ResponseEntity<UserDto> register(@RequestBody RegistrationRequest request) {
        User user = userRepository.save(new User(request.getLogin(), passwordEncoder.encode(request.getPassword())));
        return ResponseEntity.ok(new UserDto(user.getId(), user.getLogin()));
    }

    @PostMapping("login")
    public ResponseEntity<UserDto> login(@RequestBody AuthRequest request) {
        try {
            Authentication authenticate = authManager
                    .authenticate(
                            new UsernamePasswordAuthenticationToken(
                                    request.getLogin(), request.getPassword()
                            )
                    );

            User user = (User) authenticate.getPrincipal();

            return ResponseEntity.ok()
                    .header(
                            HttpHeaders.AUTHORIZATION,
                            jwtUtils.generateToken(user)
                    )
                    .body(new UserDto(user.getId(), user.getLogin()));
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
