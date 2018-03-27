package issue62;

import javax.enterprise.context.ApplicationScoped;

import org.eclipse.microprofile.auth.JWTAuthenticationMechanismDefinition;

@JWTAuthenticationMechanismDefinition(
)
@ApplicationScoped
public class SomeAuthMech {
}
