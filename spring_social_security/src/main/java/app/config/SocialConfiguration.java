package app.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.social.config.annotation.ConnectionFactoryConfigurer;
import org.springframework.social.facebook.connect.FacebookConnectionFactory;
import org.springframework.social.google.connect.GoogleConnectionFactory;

@Configuration
public class SocialConfiguration {
	@Autowired
	Environment env;

	@Bean
	public FacebookConnectionFactory getFacebookConnectionFactory() {
		return new FacebookConnectionFactory(env.getProperty("facebook.appId"),
				env.getProperty("facebook.appSecret"));
	}

	@Bean
	public GoogleConnectionFactory getGoogleConnectionFactory() {
		return new GoogleConnectionFactory(env.getProperty("google.appId"),
				env.getProperty("google.appSecret"));
	}
}
