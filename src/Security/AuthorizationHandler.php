<?php

namespace PhpSolution\JwtSecurityBundle\Security;

use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Token\Plain;
use PhpSolution\JwtSecurityBundle\Token\UserTokenProvider;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;

/**
 * Class AuthenticationHandler
 */
class AuthorizationHandler implements AuthenticationSuccessHandlerInterface, AuthenticationFailureHandlerInterface
{
    /**
     * @var UserTokenProvider
     */
    protected $userTokenProvider;

    /**
     * AuthenticationHandler constructor.
     *
     * @param UserTokenProvider $userTokenProvider
     */
    public function __construct(UserTokenProvider $userTokenProvider)
    {
        $this->userTokenProvider = $userTokenProvider;
    }

    /**
     * @param Request        $request
     * @param TokenInterface $authToken
     *
     * @return JsonResponse
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $authToken): JsonResponse
    {
        $authUser = $authToken->getUser();
        $accessToken = $this->userTokenProvider->getAccessToken($authUser);
        $refreshToken = $this->userTokenProvider->getRefreshToken($authUser, $accessToken);
        /* @var $exp \DateTime */
        $exp = $accessToken->claims()->get(RegisteredClaims::EXPIRATION_TIME);

        return $this->createAuthenticationSuccessResponse($accessToken, $refreshToken);
    }

    /**
     * @param Request                 $request
     * @param AuthenticationException $exception
     *
     * @return JsonResponse
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): JsonResponse
    {
        return new JsonResponse(['error' => $exception ? $exception->getMessage() : ''], Response::HTTP_UNAUTHORIZED);
    }

    /**
     * @param Plain $accessToken
     * @param Plain $refreshToken
     *
     * @return JsonResponse
     */
    public function createAuthenticationSuccessResponse(Plain $accessToken, Plain $refreshToken): JsonResponse
    {
        /* @var $exp \DateTime */
        $exp = $accessToken->claims()->get(RegisteredClaims::EXPIRATION_TIME);

        return new JsonResponse(
            [
                'access_token' => $accessToken->__toString(),
                'expires_in' => $exp->getTimestamp(),
                'refresh_token' => $refreshToken->__toString(),
            ]
        );
    }
}
