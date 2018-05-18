<?php

namespace PhpSolution\JwtSecurityBundle\DependencyInjection\Compiler;

use Symfony\Component\Config\Definition\Exception\InvalidDefinitionException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Class AuthResponseBuilderPass
 */
class AuthResponseBuilderPass implements CompilerPassInterface
{
    /**
     * @param ContainerBuilder $container
     */
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasParameter('jwt_security.security.authorization_handler.response_builder')) {
            return;
        }

        $responseBuilderId = $container->getParameter('jwt_security.security.authorization_handler.response_builder');
        if (!$container->hasDefinition($responseBuilderId)) {
            throw new InvalidDefinitionException(sprintf('Undefined auth response builder with id: "%s"', $responseBuilderId));
        }
        $container->getDefinition('jwt_security.security.authorization_handler')
            ->setArgument(2, new Reference($responseBuilderId));
    }
}
