<?php

namespace PhpSolution\JwtSecurityBundle\Token;

use Lcobucci\JWT\Token\Plain;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Class UserAuthTokenData
 */
class UserAuthTokenData
{
    /**
     * @var UserInterface|null $user
     */
    private $user;

    /**
     * @var Plain
     */
    private $accessToken;

    /**
     * @var Plain
     */
    private $refreshToken;

    /**
     * @return UserInterface
     */
    public function getUser(): ?UserInterface
    {
        return $this->user;
    }

    /**
     * @param UserInterface|null $user
     *
     * @return UserAuthTokenData
     */
    public function setUser(?UserInterface $user): UserAuthTokenData
    {
        $this->user = $user;

        return $this;
    }

    /**
     * @return Plain
     */
    public function getAccessToken(): Plain
    {
        return $this->accessToken;
    }

    /**
     * @param Plain $accessToken
     *
     * @return UserAuthTokenData
     */
    public function setAccessToken(Plain $accessToken): UserAuthTokenData
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    /**
     * @return Plain
     */
    public function getRefreshToken(): Plain
    {
        return $this->refreshToken;
    }

    /**
     * @param Plain $refreshToken
     *
     * @return UserAuthTokenData
     */
    public function setRefreshToken(Plain $refreshToken): UserAuthTokenData
    {
        $this->refreshToken = $refreshToken;

        return $this;
    }
}
