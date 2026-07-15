<?php

/*
 * This file is part of the 2amigos/yii2-usuario project.
 *
 * (c) 2amigOS! <http://2amigos.us/>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Da\User\Controller\api\v1;

use Da\User\Event\FormEvent;
use Da\User\Form\LoginForm;
use Da\User\Traits\ContainerAwareTrait;
use Da\User\Traits\ModuleAwareTrait;
use Yii;
use yii\filters\auth\CompositeAuth;
use yii\rest\Controller;
use yii\web\Cookie;
use yii\web\UnauthorizedHttpException;

class SecurityController extends Controller
{
    use ContainerAwareTrait;
    use ModuleAwareTrait;

    public function behaviors()
    {
        $behaviors = parent::behaviors();

        // Remove authentication filter added by parent (if any)
        unset($behaviors['authenticator']);

        $behaviors['authenticator'] = [
            'class' => CompositeAuth::class,
            'except' => ['login', 'verify'],
        ];

        return $behaviors;
    }

    public function actionLogin()
    {
        /**
         * @var LoginForm $form
         */
        $form = $this->make(LoginForm::class);

        /**
         * @var FormEvent $event
         */
        $event = $this->make(FormEvent::class, [$form]);

        $form->load(Yii::$app->getRequest()->getBodyParams(), '');

        if ($form->validate()) {
            $user = $form->getUser();

            if ($this->module->enableTwoFactorAuthentication && $user->auth_tf_enabled) {
                $payload = json_encode(['id' => $user->id, 'expire' => time() + 300]);
                $tfaToken = Yii::$app->security->encryptByKey($payload, Yii::$app->request->cookieValidationKey);

                return [
                    'tfa_required' => true,
                    'tfa_token' => base64_encode($tfaToken),
                ];
            }
        }

        $this->trigger(FormEvent::EVENT_BEFORE_LOGIN, $event);
        if ($form->login()) {
            $form->getUser()->updateAttributes([
                'last_login_at' => time(),
                'last_login_ip' => $this->module->disableIpLogging ? '127.0.0.1' : Yii::$app->request->getUserIP(),
            ]);

            $this->trigger(FormEvent::EVENT_AFTER_LOGIN, $event);

            $token = $form->getUser()->getAccessToken();

            // Besides returning the token in the body, expose it as an httpOnly cookie so
            // clients can persist it without handling the token in JS.
            $this->sendAccessTokenCookie($token);

            return [
                'token' => $token,
            ];
        }
        $this->trigger(FormEvent::EVENT_FAILED_LOGIN, $event);

        throw new UnauthorizedHttpException("Login failed. You are unauthorized to perform actions");
    }

    public function actionVerify()
    {
        $body = Yii::$app->getRequest()->getBodyParams();
        $tfaToken = isset($body['tfa_token']) ? base64_decode($body['tfa_token']) : null;
        $code = isset($body['code']) ? $body['code'] : null;

        if (!$tfaToken || !$code) {
            throw new \yii\web\BadRequestHttpException('tfa_token and code are required');
        }

        $payloadJson = Yii::$app->security->decryptByKey($tfaToken, Yii::$app->request->cookieValidationKey);
        if (!$payloadJson) {
            throw new UnauthorizedHttpException('Invalid TFA token');
        }

        $payload = json_decode($payloadJson, true);
        if (!$payload || !isset($payload['id']) || !isset($payload['expire']) || time() > $payload['expire']) {
            throw new UnauthorizedHttpException('Expired or invalid TFA token');
        }

        $userQuery = $this->make(\Da\User\Query\UserQuery::class);
        $user = $userQuery->whereId($payload['id'])->one();

        if (!$user || !$user->auth_tf_enabled) {
            throw new UnauthorizedHttpException('Invalid user or TFA not enabled');
        }

        // Validate the code
        $validators = $this->module->twoFactorAuthenticationValidators;
        $type = $user->auth_tf_type;
        $class = \yii\helpers\ArrayHelper::getValue($validators, $type . '.class');
        
        if (!$class) {
            throw new \yii\web\ServerErrorHttpException('2FA validator not configured properly.');
        }

        $validator = $this->make($class, [$user, $code, $this->module->twoFactorAuthenticationCycles]);
        
        if (!$validator->validate()) {
            $codeDurationTime = \yii\helpers\ArrayHelper::getValue($validators, $type . '.codeDurationTime', 300);
            throw new UnauthorizedHttpException($validator->getUnsuccessLoginMessage($codeDurationTime));
        }

        $user->updateAttributes([
            'last_login_at' => time(),
            'last_login_ip' => $this->module->disableIpLogging ? '127.0.0.1' : Yii::$app->request->getUserIP(),
        ]);

        $form = $this->make(LoginForm::class);
        $form->setUser($user);
        $event = $this->make(FormEvent::class, [$form]);
        $this->trigger(FormEvent::EVENT_AFTER_LOGIN, $event);

        $token = $user->getAccessToken();
        $this->sendAccessTokenCookie($token);

        return [
            'token' => $token,
        ];
    }

    /**
     * Sets the access token as an httpOnly cookie on the response, honouring the module options
     * ({@see Module::$apiTokenCookieName}, `apiTokenCookieDuration`, `apiTokenCookieSameSite`,
     * `apiTokenCookieRaw`). No-op when the cookie name is empty.
     *
     * @param string $token the access token to store
     */
    protected function sendAccessTokenCookie($token)
    {
        $name = $this->module->apiTokenCookieName;
        if (empty($name)) {
            return;
        }

        $duration = (int) $this->module->apiTokenCookieDuration;
        $expire = $duration > 0 ? time() + $duration : 0;
        $sameSite = $this->module->apiTokenCookieSameSite;
        $secure = Yii::$app->request->isSecureConnection;

        if ($this->module->apiTokenCookieRaw) {
            // Build the Set-Cookie header manually: the response cookie collection would sign the
            // value (serialized + HMAC) when cookieValidationKey is set, whereas an SSR/BFF layer
            // needs the bare token to forward it as a Bearer credential.
            $parts = [rawurlencode($name) . '=' . $token, 'Path=/'];
            if ($expire > 0) {
                $parts[] = 'Expires=' . gmdate('D, d-M-Y H:i:s', $expire) . ' GMT';
                $parts[] = 'Max-Age=' . $duration;
            }
            $parts[] = 'HttpOnly';
            if (!empty($sameSite)) {
                $parts[] = 'SameSite=' . $sameSite;
            }
            if ($secure) {
                $parts[] = 'Secure';
            }
            Yii::$app->response->headers->add('Set-Cookie', implode('; ', $parts));

            return;
        }

        Yii::$app->response->cookies->add(new Cookie([
            'name' => $name,
            'value' => $token,
            'httpOnly' => true,
            'secure' => $secure,
            'sameSite' => !empty($sameSite) ? $sameSite : Cookie::SAME_SITE_STRICT,
            'expire' => $expire,
        ]));
    }
}
