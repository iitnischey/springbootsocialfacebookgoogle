package app.repositories;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.social.connect.ConnectionData;
import org.springframework.stereotype.Repository;

import app.entities.AppUser;
import app.entities.AppUserDetails;
import app.entities.descriptors.Role;
import app.entities.descriptors.SignInProvider;

@Repository
public class StorageProvider {
	@Autowired
	CustomerRepository cRepo;
	
	@Autowired
	PasswordEncoder passwordEncoder;
	
	@Autowired
	UserDetailsRepository userDetailsRepo;
	
	public String registerUser(String username, String password) {
		String pass = passwordEncoder.encode(password);
		AppUser c = new AppUser();
		c.setUsername(username);
		c.setPassword(pass);
		c.setRole(Role.ROLE_USER);
		c.setSignInProvider(SignInProvider.SELF);
		cRepo.save(c);
		return c.getUsername();
	}
	public String registerSocialUser(String username, SignInProvider provider, ConnectionData data) {
		AppUser c = new AppUser();
		c.setUsername(username);
		c.setRole(Role.ROLE_USER);
		c.setSignInProvider(provider);
		AppUserDetails ud = new AppUserDetails();
		ud.setName(data.getDisplayName());
		ud.setOtherDetails(data.getProfileUrl());
		userDetailsRepo.save(ud);
		c.setUserDetails(ud);
		cRepo.save(c);
		return c.getUsername();
	}
	public List<AppUser> getAllCustomers() {
		Iterable<AppUser> customers = cRepo.findAll();
		List<AppUser> result = new ArrayList<AppUser>();
		Iterator<AppUser> customersItr = customers.iterator();
		while (customersItr.hasNext()) {
			result.add(customersItr.next());
		}
		return result;
	}

	public AppUser getCustomer(String username) {
		return cRepo.findByUsername(username);
	}

}
