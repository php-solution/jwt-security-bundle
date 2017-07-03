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
            pattern: '^/login'
            stateless: true
            anonymous: true
            json_login:
                check_path: '/login'
                success_handler: 'jwt_security.security.authorization_handler'
                failure_handler: 'jwt_security.security.authorization_handler'
        api_secured:
            pattern: '^/'
            stateless: true
            provider: 'in_memory_users'
            guard:
                authenticators: ['jwt_security.security.authenticator']
access_control:
    - { path: '^/login', roles: 'IS_AUTHENTICATED_ANONYMOUSLY' }
    - { path: '^/', roles: 'IS_AUTHENTICATED_FULLY' }        
````
Add route for check login:
````YAML
api_security:
  resource: '@JwtSecurityBundle/Resources/config/routing.yml'     
````
or 
````YAML
_jwt_security_login:
    path: '/login'
    defaults: { _controller: 'PhpSolution\JwtSecurityBundle\Controller\SecurityController::loginAction', _format: 'json' }
````