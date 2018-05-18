<?php

namespace PhpSolution\JwtSecurityBundle\Security;

use Lcobucci\JWT\Token\RegisteredClaims;
use PhpSolution\JwtSecurityBundle\Token\UserAuthTokenData;
use PhpSolution\JwtSecurityBundle\Token\UserTokenProvider;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
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
     * @var AuthResponseBuilderInterface|null
     */
    protected $authResponseBuilder;

    /**
     * @var array
     */
    protected $exMessages;

    /**
     * AuthorizationHandler constructor.
     *
     * @param UserTokenProvider                 $userTokenProvider
     * @param array                             $exMessages
     * @param AuthResponseBuilderInterface|null $authResponseBuilder
     */
    public function __construct(UserTokenProvider $userTokenProvider, array $exMessages = [], AuthResponseBuilderInterface $authResponseBuilder = null)
    {
        $this->userTokenProvider = $userTokenProvider;
        $this->exMessages = $exMessages;
        $this->authResponseBuilder = $authResponseBuilder;
    }

    /**
     * @param Request        $request
     * @param TokenInterface $authToken
     *
     * @return JsonResponse
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $authToken): JsonResponse
    {
        return $this->getAuthenticationUserResponse($authToken->getUser());
    }

    /**
     * @param Request                 $request
     * @param AuthenticationException $exception
     *
     * @return JsonResponse
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): JsonResponse
    {
        $error = $exception->getMessage();
        $authExceptionClass = get_class($exception);
        $prevException = $exception->getPrevious();
        $preAuthExceptionClass = get_class($prevException);

        foreach ($this->exMessages as $exClass => $exMessage) {
            if (
                $authExceptionClass === $exClass
                || is_subclass_of($exception, $exClass)
                || $preAuthExceptionClass === $exClass
                || is_subclass_of($prevException, $exClass)
            ) {
                $error = $exMessage;
            }
        }

        return new JsonResponse(['error' => $error], Response::HTTP_UNAUTHORIZED);
    }

    /**
     * @param UserInterface $user
     *
     * @return JsonResponse
     */
    public function getAuthenticationUserResponse(UserInterface $user): JsonResponse
    {
        $authTokenData = $this->userTokenProvider->getUserAuthenticationTokenData($user);

        return $this->getAuthenticationSuccessResponse($authTokenData);
    }

    /**
     * @see https://tools.ietf.org/html/rfc6750
     *
     * @param UserAuthTokenData $authTokenData
     *
     * @return JsonResponse
     */
    public function getAuthenticationSuccessResponse(UserAuthTokenData $authTokenData): JsonResponse
    {
        $accessToken = $authTokenData->getAccessToken();
        $refreshToken = $authTokenData->getRefreshToken();
        /* @var $exp \DateTime */
        $exp = $accessToken->claims()->get(RegisteredClaims::EXPIRATION_TIME);

        $responseData = [
            'access_token' => $accessToken->__toString(),
            'expires_in' => $exp->getTimestamp(),
            'refresh_token' => $refreshToken->__toString(),
        ];

        if ($this->authResponseBuilder instanceof AuthResponseBuilderInterface) {
            $responseData = $this->authResponseBuilder->buildAuthenticationSuccessResponseData($authTokenData, $responseData);
        }

        return new JsonResponse($responseData);
    }
}
