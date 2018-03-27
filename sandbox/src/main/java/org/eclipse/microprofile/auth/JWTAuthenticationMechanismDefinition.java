package org.eclipse.microprofile.auth;


/**
 * Annotation used to define a container AuthenticationMechanism that implements the MP-JWT authentication protocol as defined
 * by the Microprofile JWT RBAC spec and makes that implementation available as an enabled CDI bean.
 */
public @interface JWTAuthenticationMechanismDefinition {
    String publicKey() default  "#{MPConfig.config[\"org.eclipse.microprofile.auth.JWT.signerPublicKey\"]}";
    String acceptedIssuer() default "#{MPConfig.config[\"org.eclipse.microprofile.auth.JWT.issuer\"]}";
    String[] acceptedIssuers() default "#{MPConfig.config[\"org.eclipse.microprofile.auth.JWT.issuers\"]}";
    int clockSkew() default 30;
}
