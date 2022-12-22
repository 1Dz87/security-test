package by.home.securitytest.security;

import by.home.securitytest.model.User;
import by.home.securitytest.repository.UserRepository;
import by.home.securitytest.util.JwtUtils;
import io.jsonwebtoken.Claims;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;


@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    private final JwtUtils jwtTokenUtil;

    private final UserRepository repository;

    public JwtTokenFilter(JwtUtils jwtTokenUtil, UserRepository repository) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.repository = repository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.isEmpty(header) || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = header.split(" ")[1];
        Claims claims;
        try {
            claims = jwtTokenUtil.getClaims(token);
        } catch (Exception e) {
            filterChain.doFilter(request, response);
            return;
        }

        Optional<User> user = Optional.ofNullable(claims.get("login"))
                .flatMap(login -> repository.findByLogin((String) login));

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                user.orElse(null),
                null,
                user.map(User::getAuthorities).orElse(List.of()));
        SecurityContextHolder.getContext().setAuthentication(auth);
        filterChain.doFilter(request, response);
    }
}
