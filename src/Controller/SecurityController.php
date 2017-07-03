<?php

namespace PhpSolution\JwtSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Class SecurityController
 */
class SecurityController
{
    /**
     * @return JsonResponse
     */
    public function loginAction(): JsonResponse
    {
        return new JsonResponse();
    }
}