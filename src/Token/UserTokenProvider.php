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
    protected $tokenTypeName;

    /**
     * UserTokenProvider constructor.
     *
     * @param JwtManager $jwtManager
     * @param string     $tokenTypeName
     * @param string     $claimUsername
     */
    public function __construct(JwtManager $jwtManager, string $tokenTypeName, string $claimUsername = self::CLAIM_USERNAME)
    {
        $this->jwtManager = $jwtManager;
        $this->tokenTypeName = $tokenTypeName;
        $this->claimUsername = $claimUsername;
    }

    /**
     * @param UserInterface $user
     *
     * @return Token\Plain
     */
    public function getToken(UserInterface $user): Token\Plain
    {
        return $this->jwtManager->create(
            $this->tokenTypeName,
            [$this->claimUsername => $user->getUsername()]
        );
    }

    /**
     * @param string $tokenStr
     *
     * @return mixed
     */
    public function getUsernameByToken(string $tokenStr)
    {
        /* @var $jwtToken Token\Plain */
        $jwtToken = $this->jwtManager->parse($tokenStr, $this->tokenTypeName);
        if (!$jwtToken instanceof Token\Plain) {
            throw new \RuntimeException(sprintf('Token must be instanceof "%s"', Token\Plain::class));
        }
        $claims = $jwtToken->claims();
        if (!$claims->has($this->claimUsername)) {
            throw new \RuntimeException(sprintf('Undefined username claim "%s" for token', $this->claimUsername));
        }

        return $claims->get($this->claimUsername);
    }
}