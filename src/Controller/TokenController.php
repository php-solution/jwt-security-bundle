<?php

namespace PhpSolution\JwtSecurityBundle\Controller;

use PhpSolution\JwtSecurityBundle\Security\AuthorizationHandler;
use PhpSolution\JwtSecurityBundle\Token\UserTokenProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class TokenController
 */
class TokenController
{
    /**
     * @var UserTokenProvider
     */
    private $userTokenProvider;

    /**
     * @var AuthorizationHandler
     */
    private $authorizationHandler;

    /**
     * TokenController constructor.
     *
     * @param UserTokenProvider $userTokenProvider
     */
    public function __construct(UserTokenProvider $userTokenProvider, AuthorizationHandler $authorizationHandler)
    {
        $this->userTokenProvider = $userTokenProvider;
        $this->authorizationHandler = $authorizationHandler;
    }

    /**
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function refreshAccessAction(Request $request): JsonResponse
    {
        $newAccessToken = $this->userTokenProvider->regenerateAccessTokenFromRefreshToken(
            $request->get('access_token'),
            $request->get('refresh_token')
        );
        $newRefreshToken = $this->userTokenProvider->getRefreshToken($newAccessToken);

        return $this->authorizationHandler->createAuthenticationSuccessResponse($newAccessToken, $newRefreshToken);
    }
}
