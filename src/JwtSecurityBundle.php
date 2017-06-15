<?php

namespace PhpSolution\JwtSecurityBundle;

use PhpSolution\JwtSecurityBundle\DependencyInjection\SecurityFactory;
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
        /* @var $extension \Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension */
        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new SecurityFactory());
    }
}