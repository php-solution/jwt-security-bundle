<?php

namespace PhpSolution\JwtSecurityBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Class Configuration
 */
class Configuration implements ConfigurationInterface
{
    /**
     * @return TreeBuilder
     */
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('jwt_security');
        $rootNode
            ->children()
                ->arrayNode('auth_header')
                    ->canBeUnset()
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('name')->cannotBeEmpty()->defaultValue('Authorization')->end()
                        ->scalarNode('prefix')->cannotBeEmpty()->defaultValue('Bearer ')->end()
                    ->end()
                ->end()
                ->arrayNode('token_provider')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('access_token_type')->cannotBeEmpty()->defaultValue('authentication')->end()
                        ->scalarNode('refresh_token_type')->cannotBeEmpty()->defaultValue('authentication_refresh')->end()
                        ->scalarNode('claim_user')->cannotBeEmpty()->defaultValue('user')->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}