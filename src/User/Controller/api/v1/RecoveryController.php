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
use Da\User\Factory\MailFactory;
use Da\User\Form\RecoveryForm;
use Da\User\Model\Token;
use Da\User\Query\TokenQuery;
use Da\User\Query\UserQuery;
use Da\User\Service\PasswordRecoveryService;
use Da\User\Service\ResetPasswordService;
use Da\User\Traits\ContainerAwareTrait;
use Da\User\Traits\ModuleAwareTrait;
use Yii;
use yii\rest\Controller;
use yii\web\BadRequestHttpException;
use yii\web\NotFoundHttpException;

/**
 * REST twin of {@see \Da\User\Controller\RecoveryController}: drives the whole
 * password-recovery flow over the API so a decoupled frontend (SPA/BFF) can own it.
 *
 * - `POST recovery/request` — `{ email }` → send the recovery email, always `{ ok: true }`.
 * - `GET  recovery/reset?token=` → `{ valid: bool }` (validate before showing the form).
 * - `POST recovery/reset` — `{ token, password }` → set the new password.
 *
 * The `(id, code)` pair the web flow uses is carried as one opaque {@see Token::getApiToken()
 * token}. The recovery email links to {@see \Da\User\Module::$passwordRecoveryUrl} (the
 * frontend), not the backend web route. Responses never reveal whether an address is
 * registered or why a token failed (no user enumeration).
 */
class RecoveryController extends Controller
{
    use ContainerAwareTrait;
    use ModuleAwareTrait;

    protected $userQuery;
    protected $tokenQuery;

    public function __construct($id, $module, UserQuery $userQuery, TokenQuery $tokenQuery, array $config = [])
    {
        $this->userQuery = $userQuery;
        $this->tokenQuery = $tokenQuery;
        parent::__construct($id, $module, $config);
    }

    /**
     * {@inheritdoc}
     */
    public function behaviors()
    {
        $behaviors = parent::behaviors();

        // Recovery is a pre-authentication flow: the recovery token is the only credential.
        unset($behaviors['authenticator']);

        return $behaviors;
    }

    /**
     * {@inheritdoc}
     */
    protected function verbs()
    {
        return [
            'request' => ['POST'],
            'reset' => ['GET', 'POST'],
        ];
    }

    /**
     * Requests a recovery email. Always reports success, whether or not the address maps to an
     * account, so the endpoint cannot enumerate registered users.
     *
     * @throws NotFoundHttpException when recovery is disabled on the module
     * @return array
     */
    public function actionRequest()
    {
        if (!$this->module->allowPasswordRecovery) {
            throw new NotFoundHttpException();
        }

        /** @var RecoveryForm $form */
        $form = $this->make(RecoveryForm::class, [], ['scenario' => RecoveryForm::SCENARIO_REQUEST]);
        $form->load(Yii::$app->request->getBodyParams(), '');

        if ($form->validate()) {
            /** @var FormEvent $event */
            $event = $this->make(FormEvent::class, [$form]);
            $this->trigger(FormEvent::EVENT_BEFORE_REQUEST, $event);

            if (empty($this->module->passwordRecoveryUrl)) {
                // Without a frontend reset URL the email link would point at the backend web
                // route, defeating the API flow. Log and fall through to the generic response.
                Yii::error(
                    'API password recovery requested but Module::$passwordRecoveryUrl is not configured.',
                    __METHOD__
                );
            } else {
                $mailService = MailFactory::makeRecoveryMailerService($form->email);
                $service = $this->make(PasswordRecoveryService::class, [$form->email, $mailService]);
                $service->setResetUrlTemplate($this->module->passwordRecoveryUrl);
                if ($service->run()) {
                    $this->trigger(FormEvent::EVENT_AFTER_REQUEST, $event);
                }
            }
        }

        return ['ok' => true];
    }

    /**
     * `GET`  — validates a recovery token (`?token=`) → `{ valid: bool }`.
     * `POST` — sets a new password (`{ token, password }`) → `{ ok: true }`.
     *
     * @throws NotFoundHttpException when recovery is disabled on the module
     * @throws BadRequestHttpException on an invalid/expired token or an unmet password rule
     * @return array
     */
    public function actionReset()
    {
        if (!$this->module->allowPasswordRecovery) {
            throw new NotFoundHttpException();
        }

        $request = Yii::$app->request;

        if ($request->getIsGet()) {
            return ['valid' => $this->findRecoveryToken($request->get('token')) !== null];
        }

        $body = $request->getBodyParams();

        $token = $this->findRecoveryToken($body['token'] ?? null);
        if ($token === null) {
            throw new BadRequestHttpException(Yii::t('usuario', 'Recovery link is invalid or expired. Please try requesting a new one.'));
        }

        /** @var RecoveryForm $form */
        $form = $this->make(RecoveryForm::class, [], ['scenario' => RecoveryForm::SCENARIO_RESET]);
        $form->password = $body['password'] ?? null;

        if (!$form->validate()) {
            $errors = $form->getFirstErrors();
            throw new BadRequestHttpException($errors ? reset($errors) : Yii::t('usuario', 'Password reset failed'));
        }

        if (!$this->make(ResetPasswordService::class, [$form->password, $token->user])->run()) {
            throw new BadRequestHttpException(Yii::t('usuario', 'Password reset failed'));
        }

        // Single use: drop the token so the link cannot be replayed.
        $token->delete();

        return ['ok' => true];
    }

    /**
     * Resolves an opaque API token to a live, non-expired recovery {@see Token} whose user still
     * exists, or `null`. A malformed token, a missing row, expiry or a dangling user all collapse
     * to `null` so callers cannot distinguish the failure modes.
     *
     * @param mixed $apiToken
     * @return Token|null
     */
    protected function findRecoveryToken($apiToken)
    {
        [$userId, $code] = Token::splitApiToken($apiToken);
        if ($userId === null) {
            return null;
        }

        /** @var Token|null $token */
        $token = $this->tokenQuery->whereUserId($userId)->whereCode($code)->whereIsRecoveryType()->one();

        if ($token === null || $token->getIsExpired() || $token->user === null) {
            return null;
        }

        return $token;
    }
}
