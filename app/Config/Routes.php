<?php

use CodeIgniter\Router\RouteCollection;

/**
 * @var RouteCollection $routes
 */
$routes->get('/', 'Home::index');



$routes->group('api', ['namespace' => 'App\Controllers\API'], static function ($routes) {

    $routes->group('auth', static function ($routes) {
        $routes->post('login', 'Auth::login', ['as' => 'login']);
        $routes->post('refresh', 'Auth::refresh', ['as' => 'validateRefreshToken']);
    });


    $routes->group('', ['filter' => 'api-auth', 'namespace' => 'App\Controllers\API'], static function ($routes) {
        $routes->get('user', 'Auth::userdata', ['as' => 'userdata']);
    });
});
