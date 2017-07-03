<?php

namespace PhpSolution\JwtSecurityBundle\Security;

use Lcobucci\JWT\Token\RegisteredClaims;
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
     * @param TokenInterface $token
     *
     * @return JsonResponse
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token): JsonResponse
    {
        $token = $this->userTokenProvider->getToken($token->getUser());
        $exp = $token->claims()->get(RegisteredClaims::EXPIRATION_TIME);

        return new JsonResponse(['token' => $token->__toString(), 'exp' => $exp]);
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
}