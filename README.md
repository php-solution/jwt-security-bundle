# JwtSecurityBundle
This bundle allows developer to use JWT for authorization/authentication on api application. 

## Configuration
Configure JWT in your config.yaml:
````YAML
jwt:
  default_configuration: 'common'
  configurations:
    common:
      asymmetric: true
      signer:
        class: 'Lcobucci\JWT\Signer\Rsa\Sha512'
      signing_key:
        content: 'file://%kernel.project_dir%/etc/jwt/keys/private.pem'
        pass: 'test'
      verification_key:
        content: 'file://%kernel.project_dir%/etc/jwt/keys/public.pub'
  types:
    authentication:
      configuration: 'common'
      exp: 3600
````
Configure authorization JWT in your config.yaml:
````YAML
jwt_security:
  auth_header:
      name: 'Authorization'
      prefix: 'Bearer '
  token_provider:
      token_type: 'authentication'
      claim_user: 'user'
````
Configure security in your security.yaml:
````YAML
security:
    providers:
        your_user_provider: # provider name
            ...    
    firewalls:
        api_login:
            pattern:  '^/api/login'
            stateless: true
            anonymous: true
            form_login:
                check_path: '/api/login_check' # must be added to routing.yaml
                success_handler: 'jwt_security.security.authorization_handler'
                failure_handler: 'jwt_security.security.authorization_handler'
                require_previous_session: false
        api_secured:
            pattern: '^/api'
            stateless: true
            provider: 'your_user_provider' # provider name
            guard:
                authenticators: ['jwt_security.security.authenticator']
    access_control:
        - { path: '^/api/login', roles: 'IS_AUTHENTICATED_ANONYMOUSLY' }
        - { path: '^/api', roles: 'IS_AUTHENTICATED_FULLY' }        
````
Add route for check login:
````YAML
api_login_check:
    path: '/api/login_check'        
````