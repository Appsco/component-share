<?php

namespace BWC\Share\Net\HttpClient;

use BWC\Share\Net\ContentType;


class HttpClient implements HttpClientInterface
{
    private $_curl;

    private $_timeout_ms = 10000;

    protected $_accept;

    private $_header;

    private $_statusCode;

    private $_errorText;


    function __construct() {
        $this->_curl = curl_init();
        curl_setopt($this->_curl, CURLOPT_RETURNTRANSFER, true);
    }


    function getTimeoutMS() {
        return $this->_timeout_ms;
    }

    function setTimeoutMS($milliseconds) {
        $this->_timeout_ms = $milliseconds;
    }

    /**
     * @param $path
     * @return void
     */
    public function setCaPath($path)
    {
        if ($path) {
            curl_setopt($this->_curl, CURLOPT_CAPATH, $path);
        }
    }

    /**
     * @param $file
     * @return void
     */
    public function setCaFile($file)
    {
        if ($file) {
            curl_setopt($this->_curl, CURLOPT_CAINFO, $file);
        }
    }

    /**
     * @param bool $value
     * @return void
     */
    public function looseSslCheck($value)
    {
        if ($value) {
            curl_setopt($this->_curl, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($this->_curl, CURLOPT_SSL_VERIFYHOST, 0);
        } else {
            curl_setopt($this->_curl, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($this->_curl, CURLOPT_SSL_VERIFYHOST, 2);
        }
    }

    /**
     * @return int
     */
    function getStatusCode() {
        return $this->_statusCode;
    }

    /**
     * @return string
     */
    function getErrorText() {
        return $this->_errorText;
    }
    /**
     * @return string
     */
    function getHeader() {
        return $this->_header;
    }



    /**
     * @param string $username
     * @param string $password
     * @return void
     */
    function setCredentials($username, $password) {
        curl_setopt($this->_curl, CURLOPT_USERPWD, $username.':'.$password);
    }


    /**
     * @param string $type   mime type for Accept http header, like text/xml or application/json
     * @return void
     */
    function accept($type) {
        $this->_accept = $type;
    }



    /**
     * @param string $url
     * @param array $queryData
     * @param array $arrHeaders
     * @return string
     */
    function get($url, array $queryData = array(), array $arrHeaders = null) {
        $arrHeaders[] = 'Content-length: 0';
        $result = $this->request($url, 'GET', $queryData, null, null, $arrHeaders);
        return $result;
    }


    function post($url, array $queryData = array(), $postData, $contentType = null, array $arrHeaders = null) {
        $result = $this->request($url, 'POST', $queryData, $postData, $contentType, $arrHeaders);
        return $result;
    }

    /**
     * @param string $url
     * @param array $queryData
     * @param array $arrHeaders
     * @return string
     */
    function delete($url, array $queryData = array(), array $arrHeaders = null) {
        $result = $this->request($url, 'DELETE', $queryData, null, null, $arrHeaders);
        return $result;
    }


    /**
     * @param $url
     * @param $method
     * @param array $queryData
     * @param array|string $postData
     * @param null $contentType
     * @param array $arrHeaders
     * @return string
     */
    function request($url, $method, array $queryData, $postData, $contentType = null, array $arrHeaders = null) {
        $this->_header = null;
        $header = $arrHeaders ?: array();
        $header[] = sprintf('Host: %s', parse_url($url, PHP_URL_HOST));
        if ($this->_accept && !isset($header['Accept']))
            $header[] = 'Accept: '.$this->_accept;
        if ($queryData) {
            $url = rtrim($url, '?');
            $url .= '?'.http_build_query($queryData);
        }
        if ($contentType) {
            $header[] = 'Content-Type: '.$contentType;
        }
        if ($postData) {
            if (is_array($postData)) {
                $postData = http_build_query($postData);
            } else if (is_object($postData)) {
                $postData = urlencode(json_encode($postData));
            } else if (!$contentType) {
                $postData = urlencode((string)$postData);
            } else {
                $postData = (string)$postData;
            }
            curl_setopt($this->_curl, CURLOPT_POSTFIELDS, $postData);
            $header[] = 'Content-Length: '.strlen($postData);
            $header[] = 'Content-Type: '.($contentType ?: ContentType::FORM_URLENCODED);
        }
        curl_setopt($this->_curl, CURLOPT_URL, $url);
        curl_setopt($this->_curl, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($this->_curl, CURLOPT_HEADER, 1);
        curl_setopt($this->_curl, CURLOPT_HTTPHEADER, $header);
        curl_setopt($this->_curl, CURLOPT_CONNECTTIMEOUT_MS, $this->_timeout_ms ?: 10000);
        $response = curl_exec($this->_curl);
        $header_size = curl_getinfo($this->_curl, CURLINFO_HEADER_SIZE);
        $this->_header = substr($response, 0, $header_size);
        $body = substr($response, $header_size);
        $this->_statusCode = curl_getinfo($this->_curl, CURLINFO_HTTP_CODE);
        $this->_errorText = curl_error($this->_curl);
        return $body;
    }

}
