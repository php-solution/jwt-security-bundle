<?php

namespace PhpSolution\JwtSecurityBundle\Token;

use Lcobucci\JWT\Token;
use PhpSolution\JwtBundle\Jwt\JwtManager;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Class TokenUserProvider
 */
class UserTokenProvider
{
    public const CLAIM_USERNAME = 'user';
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
    public function getAccessToken(UserInterface $user): Token\Plain
    {
        return $this->createTokenForUser($user->getUsername(), $this->accessTokenTypeName);
    }

    /**
     * @param null|UserInterface $user
     * @param Token\Plain        $accessToken
     *
     * @return Token\Plain
     */
    public function getRefreshToken(Token\Plain $accessToken, UserInterface $user = null): Token\Plain
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
     * @param string $accessToken
     *
     * @return string
     */
    public function getRefreshTokenFromAccessToken(string $accessToken): string
    {
        $claims = $this->jwtManager->parseTokenWithClaims($accessToken, $this->accessTokenTypeName, [$this->claimUsername])->claims();

        return $this->createTokenForUser(
            $claims->get($this->claimUsername),
            $this->refreshTokenTypeName,
            [self::CLAIM_ACCESS_TOKEN => $accessToken->__toString()]
        );
    }

    /**
     * @param string $accessToken
     * @param string $refreshToken
     *
     * @return Token\Plain
     */
    public function regenerateAccessTokenFromRefreshToken(string $accessToken, string $refreshToken): Token\Plain
    {
        $tokenClaims = $this->jwtManager->parseTokenWithClaims($refreshToken, $this->accessTokenTypeName, [$this->claimUsername, self::CLAIM_ACCESS_TOKEN])->claims();
        if ($tokenClaims->get(self::CLAIM_ACCESS_TOKEN) !== $accessToken) {
            throw new \InvalidArgumentException('Invalid refresh token');
        }
        $userName = (string) $tokenClaims->get($this->claimUsername);

        return $this->createTokenForUser($userName, $this->accessTokenTypeName);
    }

    /**
     * @param string $tokenStr
     *
     * @return string
     */
    public function getUsernameByToken(string $tokenStr): string
    {
        $tokenClaims = $this->parseTokenWithClaims($tokenStr, $this->accessTokenTypeName, [$this->claimUsername])->claims();

        return (string) $tokenClaims->get($this->claimUsername);
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