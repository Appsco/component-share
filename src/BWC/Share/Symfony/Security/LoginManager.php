<?php

namespace BWC\Share\Symfony\Security;

use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;


class LoginManager
{
    /** @var TokenStorageInterface */
    private $_tokenStorage;

    /** @var string */
    private $_providerKey;

    /** @var SessionInterface */
    private $_session;

    /** @var string */
    private $_sessionAuthKey;



    public function __construct(
        TokenStorageInterface $tokenStorage,  // @security.token_storage
        $providerKey,                               // main - firewall name
        SessionInterface $session,                  // @session
        $sessionAuthKey                             // _security_primary_auth|_security_secured_area  = '_security' + contextName
    ) {
        $this->_tokenStorage = $tokenStorage;
        $this->_providerKey = $providerKey;
        $this->_session = $session;
        $this->_sessionAuthKey = $sessionAuthKey;
    }



    public function login($user, array $attributes = null, $providerKey = null)
    {
        if (!$providerKey) {
            $providerKey = $this->_providerKey;
        }

        if ($user instanceof UserInterface) {
            $token = new UsernamePasswordToken($user, null, $providerKey, $user->getRoles());
        } else {
            $token = new AnonymousToken($providerKey, $user ?: 'anon.');
        }

        if ($attributes) {
            $token->setAttributes($attributes);
        }

        $this->loginToken($token);
    }


    public function loginToken(TokenInterface $token)
    {
        $this->_tokenStorage->setToken($token);
        $this->_session->set($this->_sessionAuthKey, serialize($token));
    }


    /**
     * @return null|TokenInterface
     */
    public function getToken()
    {
        return $this->_tokenStorage->getToken();
    }

}
