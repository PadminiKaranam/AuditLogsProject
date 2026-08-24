package com.persistent.audit.security;

import java.io.IOException;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final JwtAuthenticationFilter jwtAuthenticationFilter;

	public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(List.of(
				"http://localhost:8080", "http://localhost:8081", "http://localhost:8082"));
		configuration.setAllowedMethods(List.of("GET", "PUT", "POST"));
		configuration.setAllowedHeaders(List.of("Authorization"));
		configuration.setExposedHeaders(List.of("Content-Disposition"));
		configuration.setAllowCredentials(false);
		configuration.setMaxAge(3600L);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
				.csrf(csrf -> csrf.disable())
				.cors(Customizer.withDefaults())
				.headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(auth -> auth
						.requestMatchers(HttpMethod.POST, "/audit/auth/login").permitAll()
						.requestMatchers("/h2-console/**").permitAll()
						.requestMatchers(HttpMethod.POST, "/audit/createEvent").hasRole("ADMIN")
						.requestMatchers(HttpMethod.GET, "/audit/verify").hasRole("ADMIN")
						.requestMatchers(HttpMethod.PUT, "/audit/checkForRetention").hasRole("ADMIN")
						.requestMatchers(HttpMethod.POST, "/audit/checkForRetention").hasRole("ADMIN")
						.requestMatchers(HttpMethod.PUT, "/audit/redact").hasRole("ADMIN")
						.requestMatchers(HttpMethod.POST, "/audit/redact").hasRole("ADMIN")
						.requestMatchers(HttpMethod.GET, "/audit/events").hasAnyRole("ADMIN", "REGULATOR")
						.requestMatchers(HttpMethod.GET, "/audit/export").hasAnyRole("ADMIN", "REGULATOR")
						.anyRequest().authenticated())
				.exceptionHandling(exceptions -> exceptions
						.authenticationEntryPoint((request, response, ex) ->
								writeJson(response, HttpStatus.UNAUTHORIZED, "Unauthorized"))
						.accessDeniedHandler((request, response, ex) ->
								writeJson(response, HttpStatus.FORBIDDEN, "Access Forbidden")))
				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}

	static void writeJson(HttpServletResponse response, HttpStatus status, String message) throws IOException {
		response.setStatus(status.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.getWriter().write("{\"status\":" + status.value() + ",\"error\":\"" + message + "\"}");
	}
}
