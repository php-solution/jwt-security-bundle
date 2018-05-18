<?php

namespace PhpSolution\JwtSecurityBundle\Security;

use PhpSolution\JwtSecurityBundle\Token\RequestTokenExtractor;
use PhpSolution\JwtSecurityBundle\Token\UserTokenProvider;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

/**
 * Class Authenticator
 */
class Authenticator extends AbstractGuardAuthenticator
{
    /**
     * @var RequestTokenExtractor
     */
    protected $requestTokenExtractor;

    /**
     * @var UserTokenProvider
     */
    protected $userTokenProvider;

    /**
     * Authenticator constructor.
     *
     * @param UserTokenProvider     $userTokenProvider
     * @param RequestTokenExtractor $requestTokenExtractor
     */
    public function __construct(UserTokenProvider $userTokenProvider, RequestTokenExtractor $requestTokenExtractor)
    {
        $this->userTokenProvider = $userTokenProvider;
        $this->requestTokenExtractor = $requestTokenExtractor;
    }

    /**
     * @param Request                      $request
     * @param AuthenticationException|null $authException
     *
     * @return JsonResponse
     */
    public function start(Request $request, AuthenticationException $authException = null): JsonResponse
    {
        return new JsonResponse(
            ['message' => $authException ? $authException->getMessage() : ''],
            Response::HTTP_UNAUTHORIZED
        );
    }

    /**
     * @param Request $request
     *
     * @return array
     */
    public function getCredentials(Request $request): ? array
    {
        try {
            return ['token' => $this->requestTokenExtractor->extract($request)];
        } catch (\Exception $e) {
            throw new AuthenticationException('Authentication token was not found');
        }
    }

    /**
     * @param mixed                 $credentials
     * @param UserProviderInterface $userProvider
     *
     * @return null|UserInterface
     */
    public function getUser($credentials, UserProviderInterface $userProvider): ?UserInterface
    {
        if (!is_array($credentials) || !array_key_exists('token', $credentials) || empty($credentials['token'])) {
            throw new AuthenticationException('Undefined credentials token');
        }

        $username = $this->userTokenProvider->getUsernameByToken($credentials['token']);
        if (empty($username)) {
            throw new AuthenticationException('Empty username for token');
        }

        return $userProvider->loadUserByUsername($username);
    }

    /**
     * @param Request                 $request
     * @param AuthenticationException $exception
     *
     * @return JsonResponse
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): JsonResponse
    {
        return new JsonResponse(
            [
                'code' => Response::HTTP_UNAUTHORIZED,
                'message' => $exception->getMessage(),
            ],
            Response::HTTP_UNAUTHORIZED
        );
    }

    /**
     * @param Request        $request
     * @param TokenInterface $token
     * @param string         $providerKey
     *
     * @return null|Response
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey): ?Response
    {
        return null;
    }

    /**
     * @param mixed         $credentials
     * @param UserInterface $user
     *
     * @return bool
     */
    public function checkCredentials($credentials, UserInterface $user): bool
    {
        return true;
    }

    /**
     * @return bool
     */
    public function supportsRememberMe(): bool
    {
        return false;
    }

    /**
     * Does the authenticator support the given Request?
     *
     * If this returns false, the authenticator will be skipped.
     *
     * @param Request $request
     *
     * @return bool
     */
    public function supports(Request $request): bool
    {
        return true;
    }
}