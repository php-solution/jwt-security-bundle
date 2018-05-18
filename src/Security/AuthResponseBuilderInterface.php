<?php

namespace PhpSolution\JwtSecurityBundle\Security;

use PhpSolution\JwtSecurityBundle\Token\UserAuthTokenData;

/**
 * Class AuthResponseBuilderInterface
 */
interface AuthResponseBuilderInterface
{
    /**
     * @param UserAuthTokenData $authTokenData
     * @param array             $responseData
     *
     * @return array
     */
    public function buildAuthenticationSuccessResponseData(UserAuthTokenData $authTokenData, array $responseData): array;
}
