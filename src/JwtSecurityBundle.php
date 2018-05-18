<?php

namespace PhpSolution\JwtSecurityBundle;

use PhpSolution\JwtSecurityBundle\DependencyInjection\Compiler\AuthResponseBuilderPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Class JwtSecurityBundle
 */
class JwtSecurityBundle extends Bundle
{
    /**
     * @param ContainerBuilder $container
     */
    public function build(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new AuthResponseBuilderPass());
    }
}