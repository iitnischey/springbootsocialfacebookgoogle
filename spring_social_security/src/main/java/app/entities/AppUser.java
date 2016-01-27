package app.entities;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToOne;

import app.entities.descriptors.Role;
import app.entities.descriptors.SignInProvider;

@Entity
public class AppUser {
	@Id
	private String username;

	private String password;

	private Role role;

	private SignInProvider signInProvider;

	@OneToOne
	private AppUserDetails userDetails;

	public String getPassword() {
		if(password==null)
			return "notapplicable";
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public Role getRole() {
		return role;
	}

	public void setRole(Role role) {
		this.role = role;
	}

	public SignInProvider getSignInProvider() {
		return signInProvider;
	}

	public void setSignInProvider(SignInProvider signInProvider) {
		this.signInProvider = signInProvider;
	}

	public AppUserDetails getUserDetails() {
		return userDetails;
	}

	public void setUserDetails(AppUserDetails userDetails) {
		this.userDetails = userDetails;
	}
}
