<?php

namespace PhpSolution\JwtSecurityBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;

/**
 * Class SecurityFactory
 */
class SecurityFactory implements SecurityFactoryInterface
{
    private const API_PROVIDER_KEY = 'jwt_security.authentication.provider';
    private const API_AUTH_LISTENER_KEY = 'jwt_security.authentication.listener';
    private const DEFAULT_ACCESS_LISTENER_KEY = 'security.authentication.listener.access';

    /**
     * @param ContainerBuilder $container
     * @param string           $id
     * @param array            $config
     * @param string           $userProviderId
     * @param string           $defaultEntryPoint
     *
     * @return array
     */
    public function create(ContainerBuilder $container, $id, $config, $userProviderId, $defaultEntryPoint): array
    {
        $providerId = self::API_PROVIDER_KEY . '.' . $id;
        $container->setDefinition($providerId, new ChildDefinition(self::API_PROVIDER_KEY))
            ->replaceArgument(0, new Reference($userProviderId));

        $accessListenerId = self::DEFAULT_ACCESS_LISTENER_KEY . '.' . $id;
        $container->setDefinition($accessListenerId, new ChildDefinition(self::API_AUTH_LISTENER_KEY));

        $container->setParameter('jwt_security.user_provider', $userProviderId);
        $container->setParameter('jwt_security.get_token_path', $config['get_token_path']);

        return [$providerId, $accessListenerId, $defaultEntryPoint];
    }

    /**
     * @param NodeDefinition|ArrayNodeDefinition $builder
     *
     * @return mixed
     */
    public function addConfiguration(NodeDefinition $builder): void
    {
        $builder
            ->children()
                ->scalarNode('authenticator')->defaultValue('rest_api.credentials.authentificator')->end()
                ->scalarNode('get_token_path')->defaultValue('/api/login')->end()
            ->end();
    }

    /**
     * @return string
     */
    public function getPosition(): string
    {
        return 'pre_auth';
    }

    /**
     * @return string
     */
    public function getKey(): string
    {
        return 'jwt_authentication';
    }
}