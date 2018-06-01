<?php

namespace PhpSolution\JwtSecurityBundle\Security;

use PhpSolution\JwtSecurityBundle\Token\UserAuthTokenData;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Class AuthResponseBuilderInterface
 */
interface AuthResponseBuilderInterface
{
    /**
     * @param AuthenticationException $exception
     * @param array                   $responseData
     *
     * @return array
     */
    public function buildAuthenticationFailureResponseData(AuthenticationException $exception, array $responseData): array;

    /**
     * @param UserAuthTokenData $authTokenData
     * @param array             $responseData
     *
     * @return array
     */
    public function buildAuthenticationSuccessResponseData(UserAuthTokenData $authTokenData, array $responseData): array;
}
