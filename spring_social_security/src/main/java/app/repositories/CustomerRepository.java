package app.repositories;

import org.springframework.data.repository.CrudRepository;

import app.entities.AppUser;

public interface CustomerRepository extends CrudRepository<AppUser, String> {
	AppUser findByUsername(String name);
}
