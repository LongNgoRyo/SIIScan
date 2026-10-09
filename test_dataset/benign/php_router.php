<?php
// Router don gian - xu ly URL
$routes = [
    '/' => 'HomeController@index',
    '/about' => 'PageController@about',
    '/contact' => 'PageController@contact',
];

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$handler = $routes[$uri] ?? 'ErrorController@notFound';
list($controller, $method) = explode('@', $handler);
echo "Route: $controller::$method";
?>
