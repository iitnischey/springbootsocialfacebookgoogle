package app.controllers;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.format.SignStyle;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.ConnectionData;
import org.springframework.social.connect.ConnectionKey;
import org.springframework.social.facebook.api.Facebook;
import org.springframework.social.facebook.connect.FacebookConnectionFactory;
import org.springframework.social.google.api.Google;
import org.springframework.social.google.api.impl.GoogleTemplate;
import org.springframework.social.google.connect.GoogleConnectionFactory;
import org.springframework.social.oauth2.AccessGrant;
import org.springframework.social.oauth2.GrantType;
import org.springframework.social.oauth2.OAuth2Operations;
import org.springframework.social.oauth2.OAuth2Parameters;
import org.springframework.stereotype.Controller;
import org.springframework.util.DigestUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import app.entities.AppUser;
import app.entities.descriptors.SignInProvider;
import app.repositories.StorageProvider;

@Controller
@RequestMapping(value = "/signin")
public class LoginController {

	@Autowired
	StorageProvider storage;

	@Autowired
	private Environment env;
	
	@Autowired
	private FacebookConnectionFactory facebookConnectionFactory;

	@Autowired
	private GoogleConnectionFactory googleConnectionFactory;

	@Autowired
	private UserDetailsService userDetailsService;

	@RequestMapping(value = "/login/facebook")
	public void facebookSignIn(HttpServletRequest request,
			HttpServletResponse response) {

		OAuth2Operations oauthOperations = facebookConnectionFactory
				.getOAuthOperations();
		OAuth2Parameters params = new OAuth2Parameters();
		String host = request.getServerName();
		String scheme = request.getScheme();
		int port = request.getServerPort();
		params.setRedirectUri(scheme + "://" + host + ":" + port
				+ "/signin/login/facebook/callback");
		String authorizeUrl = oauthOperations.buildAuthorizeUrl(
				GrantType.AUTHORIZATION_CODE, params);
		try {
			response.sendRedirect(authorizeUrl);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@RequestMapping(value = "/login/google")
	public void googleSignIn(HttpServletRequest request,
			HttpServletResponse response) {
		OAuth2Operations oauthOperations = googleConnectionFactory
				.getOAuthOperations();
		OAuth2Parameters params = new OAuth2Parameters();
		String host = request.getServerName();
		String scheme = request.getScheme();
		int port = request.getServerPort();
		params.setRedirectUri(scheme + "://" + host + ":" + port
				+ "/signin/login/google/callback");
		params.setScope("https://www.googleapis.com/auth/plus.me");
		String authorizeUrl = oauthOperations.buildAuthorizeUrl(
				GrantType.AUTHORIZATION_CODE, params);
		try {
			response.sendRedirect(authorizeUrl);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@RequestMapping(value = "/login/google/callback")
	public String googleSignInCallback(@RequestParam String code,
			HttpServletRequest request, HttpServletResponse response) {
		OAuth2Operations oauthOperations = googleConnectionFactory
				.getOAuthOperations();
		String authorizationCode = code;
		String host = request.getServerName();
		String scheme = request.getScheme();
		int port = request.getServerPort();
		AccessGrant accessGrant = oauthOperations.exchangeForAccess(
				authorizationCode, scheme + "://" + host + ":" + port
						+ "/signin/login/google/callback", null);
		Connection<Google> connection = googleConnectionFactory
				.createConnection(accessGrant);
		ConnectionData data = connection.createData();
		String userId = connection.getKey().getProviderUserId();
		String email = connection.fetchUserProfile().getEmail();
		AppUser user = storage.getCustomer(userId);
		if (user == null) {
			// need to create new account
			storage.registerSocialUser(userId, SignInProvider.GOOGLE, data);
			user = storage.getCustomer(userId);
		}
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority(user.getRole().toString()));
		UserDetails userDetails = new User(userId, user.getPassword(), authorities);
		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken(userDetails, null,
						authorities));
		return "redirect:/";
	}

	@RequestMapping(value = "/login/facebook/callback")
	public String facebookSignInCallback(@RequestParam String code,
			HttpServletRequest request, HttpServletResponse response) {

		OAuth2Operations oauthOperations = facebookConnectionFactory
				.getOAuthOperations();
		String authorizationCode = code;
		String host = request.getServerName();
		String scheme = request.getScheme();
		int port = request.getServerPort();
		AccessGrant accessGrant = oauthOperations.exchangeForAccess(
				authorizationCode, scheme + "://" + host + ":" + port
						+ "/signin/login/facebook/callback", null);
		Connection<Facebook> connection = facebookConnectionFactory
				.createConnection(accessGrant);
		ConnectionData data = connection.createData();
		String userId = connection.getKey().getProviderUserId();
		String email = connection.fetchUserProfile().getEmail();
		AppUser user = storage.getCustomer(userId);
		if (user == null) {
			// need to create new account
			storage.registerSocialUser(userId, SignInProvider.FACEBOOK, data);
			user = storage.getCustomer(userId);
		}
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority(user.getRole().toString()));
		UserDetails userDetails = new User(userId, user.getPassword(), authorities);
		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken(userDetails, null,
						authorities));
		return "redirect:/";
	}

	@RequestMapping(value = "/register")
	@ResponseBody
	public String regiser(@RequestParam String register_name,
			@RequestParam String register_password,
			@RequestParam String register_confirm_password) {
		if (register_confirm_password.equals(register_password)) {
			return storage.registerUser(register_name, register_password);
		}
		return null;
	}

	@RequestMapping(value = "/test/setCookie")
	@ResponseBody
	public String setCookie(HttpServletRequest request,
			HttpServletResponse response) {
		TokenBasedRememberMeServices rememberMeService = new TokenBasedRememberMeServices("mykey", userDetailsService);
		rememberMeService.onLoginSuccess(request, response, SecurityContextHolder.getContext().getAuthentication());
		return "done boss";
	}

	private Cookie _cookieGenerator() {
		long expirationTime = 15 * 24 * 60 * 60;
		UserDetails userDetails = (UserDetails) SecurityContextHolder
				.getContext().getAuthentication().getPrincipal();
		String username = userDetails.getUsername();
		String password = userDetails.getPassword();
		String password2 = userDetailsService.loadUserByUsername(username).getPassword();
		String md5Hex = _cookieMD5Contents(expirationTime, username, password2);
		String cookieContents = Base64.encodeBase64String((username + ":"
				+ expirationTime + ":" + md5Hex).getBytes());
		
		Cookie rememberMe = new Cookie("remember-me-dummy", cookieContents);
		rememberMe.setPath("/");
		rememberMe.setMaxAge((int) expirationTime);
		rememberMe.setHttpOnly(true);
		return rememberMe;
	}

	private String _cookieMD5Contents(long tokenExpiryTime, String username,
			String password) {
		String data = username + ":" + tokenExpiryTime + ":" + password + ":"
				+ "mykey";
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("No MD5 algorithm available!");
		}

		return new String(Hex.encode(digest.digest(data.getBytes())));
	}
}
