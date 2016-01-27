package app.controllers;

import java.io.IOException;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.ConnectionData;
import org.springframework.social.connect.web.ConnectController;
import org.springframework.social.facebook.api.Facebook;
import org.springframework.social.facebook.connect.FacebookConnectionFactory;
import org.springframework.social.oauth2.AccessGrant;
import org.springframework.social.oauth2.GrantType;
import org.springframework.social.oauth2.OAuth2Operations;
import org.springframework.social.oauth2.OAuth2Parameters;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpServerErrorException;

import app.entities.AppUser;
import app.repositories.StorageProvider;

@Controller
public class MainController {
	@Autowired
	StorageProvider storage;
	
//	 @Autowired
//	 Facebook facebook;

	// @RequestMapping(value = "/")
	// public String getin() {
	// return "index";
	// }

	@RequestMapping(value = "/greeting")
	public String getGreeting() {
		return "hello";
	}


	// @RequestMapping(value = "/")
	// public String facebookConnected() {
	// try {
	// if (!facebook.isAuthorized()) {
	// return "redirect:/connect/facebook";
	// }
	// String name = facebook.userOperations().getUserProfile().getName();
	// SecurityContextHolder.getContext().setAuthentication(
	// new UsernamePasswordAuthenticationToken(name, null, null));
	// return "hello";
	// } catch (NullPointerException npe) {
	// return "redirect:/connect/facebook";
	// }
	// }
	
	@RequestMapping(value="/test/fb")
	@ResponseBody
	public Object testFb() {
		return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
	}
	
	@RequestMapping(value = "/connect")
	public void _test(HttpServletResponse response) throws IOException {
		FacebookConnectionFactory connectionFactory = new FacebookConnectionFactory(
				"546008172244382", "7fe823c208adafeccdfc92f474654213");
		OAuth2Operations oauthOperations = connectionFactory
				.getOAuthOperations();
		OAuth2Parameters params = new OAuth2Parameters();
		params.setRedirectUri("http://localhost:8080/connect/callback");
		String authorizeUrl = oauthOperations.buildAuthorizeUrl(
				GrantType.AUTHORIZATION_CODE, params);
		response.sendRedirect(authorizeUrl);

	}

	@RequestMapping(value = "/connect/callback")
	@ResponseBody
	public String test1(@RequestParam String code) {
		FacebookConnectionFactory connectionFactory = new FacebookConnectionFactory(
				"546008172244382", "7fe823c208adafeccdfc92f474654213");
		OAuth2Operations oauthOperations = connectionFactory
				.getOAuthOperations();
		String authorizationCode = code;
		AccessGrant accessGrant = oauthOperations.exchangeForAccess(
				authorizationCode, "http://localhost:8080/connect/callback",
				null);
		Connection<Facebook> connection = connectionFactory
				.createConnection(accessGrant);
		ConnectionData data = connection.createData();
		connection.getKey();
		return authorizationCode;
	}
}
