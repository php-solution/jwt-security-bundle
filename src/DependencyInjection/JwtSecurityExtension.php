<?php

namespace PhpSolution\JwtSecurityBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

/**
 * Class JwtExtension
 */
class JwtSecurityExtension extends Extension
{
    /**
     * @param array            $configs
     * @param ContainerBuilder $container
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yml');

        if (isset($config['auth_header'])) {
            $container->getDefinition('jwt_security.request_token_extractor')
                ->setArgument(0, $config['auth_header']['name'])
                ->setArgument(1, $config['auth_header']['prefix']);
        }

        $container->getDefinition('jwt_security.user_token_provider')
            ->setArgument(1, $config['token_provider']['type_name'])
            ->setArgument(2, $config['token_provider']['claim_user']);
    }
}