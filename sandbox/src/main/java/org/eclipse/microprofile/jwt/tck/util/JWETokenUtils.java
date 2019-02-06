/*
 * Copyright (c) 2019 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.eclipse.microprofile.jwt.tck.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

// Utility class to produce and consume encrypted Jwt.
// largely derived from https://bitbucket.org/b_c/jose4j/wiki/JWT%20Examples
public class JWETokenUtils {
    
    private JWETokenUtils() {
        
    }
    
    /**
     * Encrypt Json to JWT.
     * @param inputJson
     * @param sendersPrivateKey
     * @param sendersKeyId
     * @param receiversPublicKey
     * @param receiversKeyId
     * @return base64url-encoded parts in the form Header.EncryptedKey.IV.Ciphertext.AuthenticationTag
     */
    public static String createEncryptedJWT(String inputJson, PrivateKey sendersPrivateKey, String sendersKeyId, 
            PublicKey receiversPublicKey, String receiversKeyId) {
        
        // A JWT is a JWS and/or a JWE with JSON claims as the payload.
        // In this example it is a JWS nested inside a JWE
        // So we first create a JsonWebSignature object.
        JsonWebSignature jws = new JsonWebSignature();
       
        
        // The payload of the JWS is JSON content of the JWT Claims
        jws.setPayload(inputJson);

        // The JWT is signed using the sender's private key
        jws.setKey(sendersPrivateKey);

        // Set the Key ID (kid) header because it's just the polite thing to do.
        // We only have one signing key in this example but a using a Key ID helps
        // facilitate a smooth key rollover process
        jws.setKeyIdHeaderValue(sendersKeyId);

        // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
        //jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        
        String jwt = null;
        try {
            // Sign the JWS and produce the compact serialization, which will be the inner JWT/JWS
            // representation, which is a string consisting of three dot ('.') separated
            // base64url-encoded parts in the form Header.Payload.Signature
            String innerJwt = jws.getCompactSerialization();
            
            // The outer JWT is a JWE
            JsonWebEncryption jwe = new JsonWebEncryption();
    
            // The output of the ECDH-ES key agreement will encrypt a randomly generated content encryption key
            jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
    
            // A content encryption key will be generated, then encrypted
            // with the receiver public key.
            // The content encryption key is used to encrypt the payload
            // with a composite AES-CBC / HMAC SHA2 encryption algorithm        
            String encAlg = ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256;
            jwe.setEncryptionMethodHeaderParameter(encAlg);
    
            // We encrypt to the receiver using their public key
            jwe.setKey(receiversPublicKey);
            jwe.setKeyIdHeaderValue(receiversKeyId);
    
            // A nested JWT requires that the cty (Content Type) header be set to "JWT" in the outer JWT
            jwe.setContentTypeHeaderValue("JWT");
    
            // The inner JWT is the payload of the outer JWT
            jwe.setPayload(innerJwt);
    
            // Produce the JWE compact serialization, which is the complete JWT/JWE representation,
            // which is a string consisting of five dot ('.') separated
            // base64url-encoded parts in the form Header.EncryptedKey.IV.Ciphertext.AuthenticationTag
            jwt = jwe.getCompactSerialization();
        }
        catch (JoseException e)  {            
            e.printStackTrace(System.out);
        }
        return jwt;
    }
    
    /**
     * Decrypt an encrypted JWT.  
     * Example only.  Real implementations would need to further customize their consumer settings. 
     * @param encryptedJWT
     * @param sendersPublicKey
     * @param receiversPrivateKey
     * @return
     */
    public static String decryptJWT(String encryptedJWT, PublicKey sendersPublicKey, PrivateKey receiversPrivateKey) {
        String result = null;
        // Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
        // be used to validate and process the JWT.
        // The specific validation requirements for a JWT are context dependent, however,
        // it typically advisable to require a (reasonable) expiration time, a trusted issuer, and
        // and audience that identifies your system as the intended recipient.
        // It is also typically good to allow only the expected algorithm(s) in the given context        
      
        AlgorithmConstraints jwsAlgConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
                AlgorithmIdentifiers.RSA_USING_SHA256);

        AlgorithmConstraints jweAlgConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
                KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);

        AlgorithmConstraints jweEncConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
                ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                //.setMaxFutureValidityInMinutes(300) // but the  expiration time can't be too crazy
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer("https://server.example.com") // whom the JWT needs to have been issued by
                .setExpectedAudience("s6BhdRkqt3") // to whom the JWT is intended for
                .setDecryptionKey(receiversPrivateKey) // decrypt with the receiver's private key
                .setVerificationKey(sendersPublicKey) // verify the signature with the sender's public key
                .setJwsAlgorithmConstraints(jwsAlgConstraints) // limits the acceptable signature algorithm(s)
                .setJweAlgorithmConstraints(jweAlgConstraints) // limits acceptable encryption key establishment algorithm(s)
                .setJweContentEncryptionAlgorithmConstraints(jweEncConstraints) // limits acceptable content encryption algorithm(s)
                .build(); // create the JwtConsumer instance

        try {
            //  Validate the JWT and process it to the Claims
            result = jwtConsumer.processToClaims(encryptedJWT).toJson();           
        } 
        catch (InvalidJwtException e) {            
            e.printStackTrace(System.out);
            return null;
        }
        
       return result;

    }
    
    public static void main(String [] args) {
        selfTestRSA();
    }
    
    public static void selfTestRSA() {
        RsaJsonWebKey senderKey = null;
        RsaJsonWebKey receiverKey = null;
        // Generate an RSA key pair, which will be used for signing and verification of the JWT, wrapped in a JWK
        try {
            senderKey = RsaJwkGenerator.generateJwk(2048);
            receiverKey = RsaJwkGenerator.generateJwk(2048);
            // Give the JWK a Key ID (kid), which is just the polite thing to do
            senderKey.setKeyId("k1");
            receiverKey.setKeyId("k2");
            
        } 
        catch (JoseException e) {            
            e.printStackTrace();
        }
        String json = readJson("src/test/resources/NeverExpires.json");
        System.out.println("Json: " + json);
        
        String eJwt = createEncryptedJWT(json, senderKey.getPrivateKey(), senderKey.getKeyId(), receiverKey.getPublicKey(), receiverKey.getKeyId());
        
        System.out.println("Encrypted JWT: " + eJwt);
        
        String result = decryptJWT(eJwt, senderKey.getPublicKey(), receiverKey.getPrivateKey());
        System.out.println("Decrypted JWT: " + result + "\n");
        
        System.out.println(result.equals(json) ? "PASS" : "FAIL");
    }
    
    public static String readJson(String jsonResName) {
        File f = new File(jsonResName);
        String buf = null;
        String result = "";
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(f));
            while(true) {
                buf = br.readLine();
                if (buf == null) {
                    break;
                } 
                result += buf;
            }
        } 
        catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } 
        return result.replaceAll(" ", "");
    }
}
