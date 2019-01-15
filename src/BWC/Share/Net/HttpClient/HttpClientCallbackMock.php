<?php

namespace BWC\Share\Net\HttpClient;

use BWC\Share\Net\HttpStatusCode;


class HttpClientCallbackMock implements HttpClientInterface
{
    private $_timeout_ms = 10000;

    public $statusCode = HttpStatusCode::OK;
    public $header;

    public $callbackRequest;


    /**
     * @return int
     */
    function getTimeoutMS() {
        return $this->_timeout_ms;
    }

    /**
     * @param int $milliseconds
     * @return void
     */
    function setTimeoutMS($milliseconds) {
        $this->_timeout_ms = $milliseconds;
    }

    /**
     * @param $path
     * @return void
     */
    public function setCaPath($path)
    {

    }

    /**
     * @param $file
     * @return void
     */
    public function setCaFile($file)
    {

    }


    /**
     * @return int
     */
    function getStatusCode() {
        return $this->statusCode;
    }

    /**
     * @return string
     */
    function getHeader() {
        return $this->header;
    }


    /**
     * @param string $username
     * @param string $password
     * @return void
     */
    function setCredentials($username, $password) {
        // TODO: Implement setCredentials() method.
    }


    /**
     * @param string $type   mime type for Accept http header, like text/xml or application/json
     * @return void
     */
    function accept($type) {
        // TODO: Implement accept() method.
    }

    /**
     * @param string $url
     * @param array $queryData
     * @param array $arrHeaders
     * @return string
     */
    function get($url, array $queryData = array(), array $arrHeaders = null) {
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
        if ($this->callbackRequest) {
            return call_user_func($this->callbackRequest, $this, $url, $method, $queryData, $postData, $contentType, $arrHeaders);
        } else {
            return '';
        }
    }

    /**
     * @param bool $value
     * @return void
     */
    public function looseSslCheck($value)
    {
        // TODO: Implement looseSslCheck() method.
    }

    /**
     * @return string
     */
    public function getErrorText()
    {
        // TODO: Implement getErrorText() method.
        return '';
    }
}
