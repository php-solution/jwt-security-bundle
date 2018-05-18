<?php

namespace PhpSolution\JwtSecurityBundle\Token;

use Lcobucci\JWT\Token;
use PhpSolution\JwtBundle\Jwt\JwtManager;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Class TokenUserProvider
 *
 * @see https://tools.ietf.org/html/rfc7519
 */
class UserTokenProvider
{
    public const CLAIM_USERNAME     = 'user';
    public const CLAIM_ACCESS_TOKEN = 'access_token';

    /**
     * @var JwtManager
     */
    protected $jwtManager;

    /**
     * @var string
     */
    protected $claimUsername;

    /**
     * @var string
     */
    protected $accessTokenTypeName;

    /**
     * @var string
     */
    protected $refreshTokenTypeName;

    /**
     * UserTokenProvider constructor.
     *
     * @param JwtManager $jwtManager
     * @param string     $accessTokenTypeName
     * @param string     $refreshTokenTypeName
     * @param string     $claimUsername
     */
    public function __construct(JwtManager $jwtManager, string $accessTokenTypeName, string $refreshTokenTypeName, string $claimUsername)
    {
        $this->jwtManager = $jwtManager;
        $this->accessTokenTypeName = $accessTokenTypeName;
        $this->refreshTokenTypeName = $refreshTokenTypeName;
        $this->claimUsername = $claimUsername;
    }

    /**
     * @param UserInterface $user
     *
     * @return Token\Plain
     */
    protected function getAccessToken(UserInterface $user): Token\Plain
    {
        return $this->createTokenForUser($user->getUsername(), $this->accessTokenTypeName);
    }

    /**
     * @param null|UserInterface $user
     * @param Token\Plain        $accessToken
     *
     * @return Token\Plain
     */
    protected function getRefreshToken(Token\Plain $accessToken, UserInterface $user = null): Token\Plain
    {
        $userName = $user instanceof UserInterface
            ? $user->getUsername()
            : $accessToken->claims()->get($this->claimUsername);

        return $this->createTokenForUser(
            $userName,
            $this->refreshTokenTypeName,
            [self::CLAIM_ACCESS_TOKEN => $accessToken->__toString()]
        );
    }

    /**
     * @param string $tokenStr
     *
     * @return string
     */
    public function getUsernameByToken(string $tokenStr): string
    {
        /* @var $jwt Token\Plain */
        $jwt = $this->jwtManager->parseTokenWithClaims($tokenStr, $this->accessTokenTypeName, [$this->claimUsername]);
        $tokenClaims = $jwt->claims();

        return (string) $tokenClaims->get($this->claimUsername);
    }

    /**
     * @param string                $accessToken
     * @param string                $refreshToken
     * @param UserProviderInterface $userProvider
     *
     * @return UserAuthTokenData
     */
    public function regenerateUserAuthenticationTokenData(string $accessToken, string $refreshToken, UserProviderInterface $userProvider): UserAuthTokenData
    {
        /* @var $oldAccessJWT Token\Plain */
        $oldAccessJWT = $this->jwtManager->parseTokenWithClaims($refreshToken, $this->accessTokenTypeName, [$this->claimUsername, self::CLAIM_ACCESS_TOKEN]);
        $oldAccessJWTClaims = $oldAccessJWT->claims();

        if ($oldAccessJWTClaims->get(self::CLAIM_ACCESS_TOKEN) !== $accessToken) {
            throw new \InvalidArgumentException('Invalid refresh token');
        }

        $username = (string) $oldAccessJWTClaims->get($this->claimUsername);
        $user = $userProvider->loadUserByUsername($username);

        return $this->getUserAuthenticationTokenData($user);
    }

    /**
     * @param UserInterface $user
     *
     * @return UserAuthTokenData
     */
    public function getUserAuthenticationTokenData(UserInterface $user): UserAuthTokenData
    {
        $accessToken = $this->getAccessToken($user);
        $refreshToken = $this->getRefreshToken($accessToken, $user);

        return (new UserAuthTokenData())
            ->setUser($user)
            ->setAccessToken($accessToken)
            ->setRefreshToken($refreshToken);
    }


    /**
     * @param string $username
     * @param string $tokenTypeName
     * @param array  $tokenClaims
     *
     * @return Token\Plain
     */
    protected function createTokenForUser(string $username, string $tokenTypeName, array $tokenClaims = []): Token\Plain
    {
        return $this->jwtManager->create(
            $tokenTypeName,
            array_merge([$this->claimUsername => $username], $tokenClaims)
        );
    }
}