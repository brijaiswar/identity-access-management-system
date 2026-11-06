package com.wisebrains.iam;

import com.wisebrains.iam.auth.TokenService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtAuthenticationFilterTest {
    private final TokenService tokenService = mock(TokenService.class);
    private final CustomUserDetailsService userDetailsService = mock(CustomUserDetailsService.class);
    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(tokenService, userDetailsService);

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void authenticatesRequestWithValidBearerToken() throws Exception {
        UserDetails details = User.withUsername("alice").password("x").roles("USER").build();
        String token = "tok" + "en";
        when(tokenService.validateJwt(token)).thenReturn(true);
        when(tokenService.getUsername(token)).thenReturn("alice");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);
        when(userDetailsService.loadUserByUsername("alice")).thenReturn(details);

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("alice", SecurityContextHolder.getContext().getAuthentication().getName());
    }

    @Test
    void continuesWithoutAuthenticationForMissingOrInvalidToken() throws Exception {
        String token = "b" + "ad";
        when(tokenService.validateJwt(token)).thenReturn(false);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
}
