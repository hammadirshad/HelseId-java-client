# HelseID Java client with Spring Security 
#### PKCE [RFC 7636] (Proof Key for Code Exchange) , PAR [RFC 9126] (Pushed Authorization Requests), and DPoP [RFC 9449]

HelseId OAuth2 flows (Authorization Code and Client Credentials) using the spring boot. It includes examples of securing API calls with oAuth2 and DPoP.

### 1. Authorization Code Flow
1. Navigate to the `authorization-code` project and start the application:
   ```bash
   cd authorization-code
   mvn spring-boot:run
   ```
2. Test the Authorization Code Flow:

   Access the application at http://localhost:8089.

   View the ID Token details at http://localhost:8089/api/token-info.


### 2. Client Credentials with API Security Validation
1. Navigate to the `authorization-code` project and start the application
   ```bash
   cd demo-api
   mvn spring-boot:run
   ```

2. Navigate to the `client-credentials` project and start the **client-credentials** application:
   ```bash
   cd client-credentials
   mvn spring-boot:run
   ``` 
3. The `ClientCredentialsExample` class in `client-credentials` will call demo-api with OAuth tokens and DPoP tokens.
