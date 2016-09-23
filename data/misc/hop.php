<?php

$server = rtrim("REPLACE_SERVER", '/');


function do_get_request($url, $optionalHeaders = null)
{
  $aContext = array(
    'http' => array(
      'method' => 'GET'
    ),
  );
  if ($optionalHeaders !== null) {
    $aContext['http']['header'] = $optionalHeaders;
  }
  $cxContext = stream_context_create($aContext);
  echo file_get_contents($url, False, $cxContext);
}


function do_post_request($url, $data, $optionalHeaders = null)
{
  $params = array('http' => array(
              'method' => 'POST',
              'content' => $data
            ));
  if ($optionalHeaders !== null) {
    $params['http']['header'] = $optionalHeaders;
  }
  $ctx = stream_context_create($params);
  $fp = @fopen($url, 'rb', false, $ctx);
  if (!$fp) {
    return '';
  }
  $response = @stream_get_contents($fp);
  if ($response === false) {
    return '';
  }
  echo $response;
}


if ($_SERVER['REQUEST_METHOD'] === 'GET') {
  $requestURI = $_SERVER['REQUEST_URI'];
  if(isset($_COOKIE['session'])) {
    return do_get_request($server.$requestURI, "Cookie: session=".str_replace(' ', '+', $_COOKIE['session']));
  }
  else {
    return do_get_request($server.$requestURI);
  }
}

else {
  // otherwise it's a POST
  $requestURI = $_SERVER['REQUEST_URI'];
  $postdata = file_get_contents("php://input");

  if(isset($_COOKIE['session'])) {
    return do_post_request($server.$requestURI, $postdata, "Cookie: session=".str_replace(' ', '+', $_COOKIE['session']));
  }
  else {
    return do_post_request($server.$requestURI, $postdata);
  }
}

?>
