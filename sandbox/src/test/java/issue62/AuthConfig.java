package issue62;

import java.security.PublicKey;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.inject.Named;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@Named("MPConfig")
@ApplicationScoped
public class AuthConfig {
    @Inject
    private Config config;
    @Inject
    @ConfigProperty(name = "org.eclipse.microprofile.auth.JWT.signerPublicKey")
    private String testKey;
    @Inject
    @ConfigProperty(name = "org.eclipse.microprofile.auth.JWT.signerPublicKey")
    private PublicKey keyFromPEM;
    @Inject
    @ConfigProperty(name = "org.eclipse.microprofile.auth.JWT.issuer")
    private String issuer;
    @Inject
    @ConfigProperty(name = "org.eclipse.microprofile.auth.JWT.issuers")
    private String[] issuers;
    @Inject
    @ConfigProperty(name = "org.eclipse.microprofile.auth.JWT.clockSkew", defaultValue = "30")
    private int clockSkew;

    public Config getConfig() {
        return config;
    }

    public void setConfig(Config config) {
        this.config = config;
    }

    public String getTestKey() {
        return testKey;
    }

    public PublicKey getKeyFromPEM() {
        return keyFromPEM;
    }

    public String getIssuer() {
        return issuer;
    }

    public String[] getIssuers() {
        return issuers;
    }

    public int getClockSkew() {
        return clockSkew;
    }
}
