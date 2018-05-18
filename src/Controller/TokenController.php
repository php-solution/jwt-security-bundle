<?php

namespace PhpSolution\JwtSecurityBundle\Controller;

use PhpSolution\JwtSecurityBundle\Security\AuthorizationHandler;
use PhpSolution\JwtSecurityBundle\Token\UserTokenProvider;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserProviderInterface;

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
     * @var UserTokenProvider
     */
    private $userProvider;

    /**
     * TokenController constructor.
     *
     * @param UserTokenProvider     $userTokenProvider
     * @param AuthorizationHandler  $authorizationHandler
     * @param UserProviderInterface $userProvider
     */
    public function __construct(UserTokenProvider $userTokenProvider, AuthorizationHandler $authorizationHandler, UserProviderInterface $userProvider)
    {
        $this->userTokenProvider = $userTokenProvider;
        $this->authorizationHandler = $authorizationHandler;
        $this->userProvider = $userProvider;
    }

    /**
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function refreshAccessAction(Request $request): JsonResponse
    {
        $refreshedAccessData = $this->userTokenProvider->regenerateUserAuthenticationTokenData(
            $request->get('access_token'),
            $request->get('refresh_token'),
            $this->userProvider
        );

        return $this->authorizationHandler->getAuthenticationSuccessResponse($refreshedAccessData);
    }
}
