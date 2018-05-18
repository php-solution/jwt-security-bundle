<?php

namespace PhpSolution\JwtSecurityBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Exception\InvalidDefinitionException;
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
            ->setArgument(1, $config['token_provider']['access_token_type'])
            ->setArgument(2, $config['token_provider']['refresh_token_type'])
            ->setArgument(3, $config['token_provider']['claim_user']);

        $this->configureAuthHandler($config, $container);
    }

    /**
     * @param array            $config
     * @param ContainerBuilder $container
     */
    private function configureAuthHandler(array $config, ContainerBuilder $container): void
    {
        $exceptionMessages = [];
        foreach ($config['auth_failure_exceptions'] as $configItem) {
            $exceptionMessages[$configItem['exception']] = $configItem['message'];
        }
        $container->getDefinition('jwt_security.security.authorization_handler')
            ->setArgument(1, $exceptionMessages);

        if (array_key_exists('auth_success_response_builder', $config) && $config['auth_success_response_builder']) {
            $responseBuilderId = $config['auth_success_response_builder'];
            $container->setParameter('jwt_security.security.authorization_handler.response_builder', $responseBuilderId);
        }
    }
}