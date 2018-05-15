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
        return $this->createTokenForUser($this->accessTokenTypeName);
    }

    /**
     * @param Token\Plain $accessToken
     *
     * @return Token\Plain
     */
    public function getRefreshToken(UserInterface $user, Token\Plain $accessToken): Token\Plain
    {
        return $this->createTokenForUser(
            $this->refreshTokenTypeName,
            [self::CLAIM_ACCESS_TOKEN => $accessToken->__toString()]
        );
    }

    /**
     * @return string
     */
    public function regenerateAccessTokenFromRefreshToken(string $accessToken, string $refreshToken): string
    {
        $tokenClaims = $this->getTokenClaims($tokenStr, $this->accessTokenTypeName, [$this->claimUsername, self::CLAIM_ACCESS_TOKEN]);
        if ($tokenClaims->get(self::CLAIM_ACCESS_TOKEN) !== $accessToken) {
            throw new \InvalidArgumentException('Invalid refresh token');
        }
        $userName = (string) $tokenClaims->get($this->claimUsername);

        return $this->createTokenForUser($userName);
    }

    /**
     * @param string $tokenStr
     *
     * @return string
     */
    public function getUsernameByToken(string $tokenStr): string
    {
        $tokenClaims = $this->getTokenClaims($tokenStr, $this->accessTokenTypeName, [$this->claimUsername]);

        return (string) $tokenClaims->get($this->claimUsername);
    }

    /**
     * @param string $tokenStr
     * @param string $tokenType
     * @param array  $requiredClaims
     */
    protected function getTokenClaims(string $tokenStr, string $tokenType, array $requiredClaims)
    {
        /* @var $jwtToken Token\Plain */
        $jwtToken = $this->jwtManager->parse($tokenStr, $tokenType);
        if (!$jwtToken instanceof Token\Plain) {
            throw new \RuntimeException(sprintf('Token must be instanceof "%s"', Token\Plain::class));
        }

        $claims = $jwtToken->claims();
        foreach ($requiredClaims as $claim) {
            if (!$claims->has($claim)) {
                throw new \RuntimeException(sprintf('Undefined claim "%s" for token', $claim));
            }
        }

        return $claims;
    }

    /**
     * @param string $username
     * @param array  $claims
     *
     * @return Token\Plain
     */
    protected function createTokenForUser(string $username, string $tokenTypeName, array $tokenClaims = []): Token\Plain
    {
        return $this->jwtManager->create(
            $tokenTypeName,
            array_merge([$this->claimUsername => $user->getUsername()], $tokenClaims)
        );
    }
}