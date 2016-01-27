package app;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import app.entities.AppUser;
import app.repositories.StorageProvider;

@Service
public class AppUserService implements UserDetailsService {

	@Autowired
	StorageProvider storageProvider;
	
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		AppUser c = storageProvider.getCustomer(username);
		if(c == null) {
			throw new UsernameNotFoundException("not found");
		}
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority(c.getRole().toString()));
		UserDetails userDetails = new User(c.getUsername(), c.getPassword(), authorities);
		return userDetails;
	}

}
