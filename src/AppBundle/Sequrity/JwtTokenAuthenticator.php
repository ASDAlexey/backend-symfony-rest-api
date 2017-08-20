<?php

namespace AppBundle\Sequrity;


use Doctrine\ORM\EntityManager;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\AuthorizationHeaderTokenExtractor;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class JwtTokenAuthenticator extends AbstractGuardAuthenticator {
    /**
     * @var JWTEncoderInterface
     */
    private $JWTEncoder;
    /**
     * @var EntityManager
     */
    private $em;

    public function __construct(JWTEncoderInterface $JWTEncoder, EntityManager $em) {

        $this->JWTEncoder = $JWTEncoder;
        $this->em = $em;
    }

    public function getCredentials(Request $request) {
        $extractor = new AuthorizationHeaderTokenExtractor('Bearer', 'Authorization');
        $token = $extractor->extract($request);

        if (!$token) return;

        return $token;
    }

    public function getUser($credentials, UserProviderInterface $userProvider) {
        $data = $this->JWTEncoder->decode($credentials);

        if (!$data) {
            throw new CustomUserMessageAuthenticationException('Invalid token');
        }

        $username = $data['username'];

        return $this->em->getRepository('AppBundle:User')->findOneBy(['username' => $username]);
    }

    public function checkCredentials($credentials, UserInterface $user) {
        return true;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception) {
        // TODO: Implement onAuthenticationFailure() method.
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey) {
        // TODO: Implement onAuthenticationSuccess() method.
    }

    public function supportsRememberMe() {
        return false;
    }

    public function start(Request $request, AuthenticationException $authException = null) {
        return new JsonResponse(['error' => 'auth required'], 401);
    }
}