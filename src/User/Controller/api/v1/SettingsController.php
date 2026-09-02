<?php

namespace Da\User\Controller\api\v1;

use Da\User\Factory\MailFactory;
use Da\User\Helper\SecurityHelper;
use Da\User\Service\RecoveryCodeGeneratorService;
use Da\User\Service\TwoFactorDisableService;
use Da\User\Service\TwoFactorEmailCodeGeneratorService;
use Da\User\Service\TwoFactorQrCodeUriGeneratorService;
use Da\User\Service\TwoFactorSmsCodeGeneratorService;
use Da\User\Traits\ContainerAwareTrait;
use Da\User\Traits\ModuleAwareTrait;
use Yii;
use yii\filters\auth\CompositeAuth;
use yii\helpers\ArrayHelper;
use yii\rest\Controller;
use yii\web\ForbiddenHttpException;
use yii\web\UnauthorizedHttpException;

class SettingsController extends Controller
{
    use ContainerAwareTrait;
    use ModuleAwareTrait;

    public function behaviors()
    {
        $behaviors = parent::behaviors();

        $behaviors['authenticator'] = [
            'class' => CompositeAuth::class,
        ];

        return $behaviors;
    }

    public function actionTwoFactor()
    {
        if (!$this->module->enableTwoFactorAuthentication) {
            throw new ForbiddenHttpException(Yii::t('usuario', 'Application not configured for two factor authentication.'));
        }

        $user = Yii::$app->user->identity;

        $choice = Yii::$app->request->getBodyParam('choice', Yii::$app->request->getQueryParam('choice', 'google-authenticator'));

        switch ($choice) {
            case 'google-authenticator':
                // This service will automatically generate a base32 secret and save it
                // to $user->auth_tf_key if one doesn't exist yet, then returns the QR Image Data URI
                $uri = $this->make(TwoFactorQrCodeUriGeneratorService::class, [$user])->run();

                return [
                    'uri' => $uri,
                    'secret' => $user->auth_tf_key
                ];
            case 'email':
                $this->make(TwoFactorEmailCodeGeneratorService::class, [$user])->run();
                return ['message' => Yii::t('usuario', 'A code has been sent to your email')];
            case 'sms':
                $this->make(TwoFactorSmsCodeGeneratorService::class, [$user])->run();
                return ['message' => Yii::t('usuario', 'A code has been sent to your phone')];
            default:
                throw new \yii\base\InvalidParamException("Invalid 2FA choice");
        }
    }

    public function actionTwoFactorEnable()
    {
        if (!$this->module->enableTwoFactorAuthentication) {
            throw new ForbiddenHttpException(Yii::t('usuario', 'Application not configured for two factor authentication.'));
        }

        $user = Yii::$app->user->identity;
        $code = Yii::$app->request->post('code');
        $choice = Yii::$app->request->post('choice', 'google-authenticator');

        $validators = $this->module->twoFactorAuthenticationValidators;
        $class = ArrayHelper::getValue($validators, $choice . '.class');
        $codeDurationTime = ArrayHelper::getValue($validators, $choice . '.codeDurationTime', 300);

        if (!$class) {
            throw new \yii\web\ServerErrorHttpException('2FA validator not configured properly.');
        }

        $object = $this->make($class, [$user, $code, $this->module->twoFactorAuthenticationCycles]);
        $success = $object->validate();

        $recoveryCodes = null;
        if ($success) {
            $user->updateAttributes([
                'auth_tf_enabled' => '1',
                'auth_tf_type' => $choice
            ]);

            // Shown once, right after (re)enabling 2FA: only the hash of each code is
            // ever persisted, so this is the only response that will ever contain them.
            $recoveryCodes = $this->make(RecoveryCodeGeneratorService::class, [$user])->run();
        }

        return [
            'success' => $success,
            'message' => $success ? $object->getSuccessMessage() : $object->getUnsuccessMessage($codeDurationTime),
            'recovery_codes' => $recoveryCodes
        ];
    }

    /**
     * Invalidates the user's existing recovery codes and issues a fresh batch, e.g.
     * after the user has used some of them up or suspects they were exposed.
     */
    public function actionTwoFactorRecoveryCodesRegenerate()
    {
        if (!$this->module->enableTwoFactorAuthentication) {
            throw new ForbiddenHttpException(Yii::t('usuario', 'Application not configured for two factor authentication.'));
        }

        $user = Yii::$app->user->identity;

        if (!$user->auth_tf_enabled) {
            throw new ForbiddenHttpException(Yii::t('usuario', 'Two factor authentication is not enabled.'));
        }

        return [
            'recovery_codes' => $this->make(RecoveryCodeGeneratorService::class, [$user])->run()
        ];
    }

    /**
     * Turns two factor authentication off for the authenticated user, after they have
     * re-proved knowledge of their account password.
     *
     * The bearer token alone is deliberately not enough: removing a second factor is a
     * privilege de-escalation, so it is gated behind a credential the token holder does
     * not automatically possess. Unlike the web
     * {@see \Da\User\Controller\SettingsController::actionTwoFactorDisable()}, this goes
     * through {@see TwoFactorDisableService} so the chosen channel and every outstanding
     * recovery code are cleared too, not just the TOTP secret.
     */
    public function actionTwoFactorDisable()
    {
        if (!$this->module->enableTwoFactorAuthentication) {
            throw new ForbiddenHttpException(Yii::t('usuario', 'Application not configured for two factor authentication.'));
        }

        $user = Yii::$app->user->identity;

        if (!$user->auth_tf_enabled) {
            throw new ForbiddenHttpException(Yii::t('usuario', 'Two factor authentication is not enabled.'));
        }

        // Accounts created through a social network never got a local password, so there is
        // no credential to re-prove here. Refuse rather than fall through to a password
        // check that could never pass.
        if (empty($user->password_hash)) {
            throw new ForbiddenHttpException(Yii::t('usuario', 'Your account has no password set.'));
        }

        // TODO: rate-limit this action. Each call is an oracle for one password guess, and
        // yii\rest\Controller's rateLimiter behavior cannot be switched on until User
        // implements yii\filters\RateLimitInterface.
        /* @var $security SecurityHelper */
        $security = $this->make(SecurityHelper::class);

        if (!$security->validatePassword((string)Yii::$app->request->post('password'), $user->password_hash)) {
            throw new UnauthorizedHttpException(Yii::t('usuario', 'Current password is not valid'));
        }

        $this->make(TwoFactorDisableService::class, [$user])->run();

        // Best-effort: the out-of-band signal that lets the legitimate user notice and react
        // if the disable was not theirs, but a mailer failure must not undo the disable that
        // already succeeded.
        try {
            MailFactory::makeTwoFactorDisabledMailerService($user)->run();
        } catch (\Throwable $e) {
            Yii::error("Failed to send 2FA-disabled notification to user {$user->id}: {$e->getMessage()}", __METHOD__);
        }

        return [
            'success' => true,
            'message' => Yii::t('usuario', 'Two factor authentication has been disabled.'),
        ];
    }
}
