package app.repositories;

import org.springframework.data.repository.CrudRepository;

import app.entities.AppUser;
import app.entities.AppUserDetails;

public interface UserDetailsRepository extends CrudRepository<AppUserDetails, Long> {
}
