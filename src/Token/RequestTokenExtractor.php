<?php

namespace PhpSolution\JwtSecurityBundle\Token;

use Symfony\Component\HttpFoundation\Request;

/**
 * Class RequestTokenExtractor
 */
class RequestTokenExtractor
{
    public const DEFAULT_HEADER_NAME = 'Authorization';
    public const DEFAULT_HEADER_PREFIX = 'Bearer ';

    /**
     * @var string
     */
    private $headerName;
    /**
     * @var string
     */
    private $headerPrefix;

    /**
     * RequestTokenExtractor constructor.
     *
     * @param string $headerName
     * @param string $headerPrefix
     */
    public function __construct(string $headerName = self::DEFAULT_HEADER_NAME, string $headerPrefix = self::DEFAULT_HEADER_PREFIX)
    {
        $this->headerName = $headerName;
        $this->headerPrefix = $headerPrefix;
    }

    /**
     * @param Request $request
     *
     * @return string
     */
    public function extract(Request $request): string
    {
        $token = null;
        if ($request->headers->has($this->headerName)) {
            $header = $request->headers->get($this->headerName);
            $token = (!empty($this->headerPrefix) && 0 === strpos($header, $this->headerPrefix))
                ? (string) substr($header, strlen($this->headerPrefix))
                : $header;
        }

        if (empty($token)) {
            throw new \RuntimeException('Undefined token on request');
        }

        return $token;
    }
}