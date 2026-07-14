<?php

namespace Da\User\Controller\api\v1;

use Da\User\Service\TwoFactorQrCodeUriGeneratorService;
use Da\User\Service\TwoFactorEmailCodeGeneratorService;
use Da\User\Service\TwoFactorSmsCodeGeneratorService;
use Da\User\Traits\ContainerAwareTrait;
use Da\User\Traits\ModuleAwareTrait;
use Yii;
use yii\filters\auth\CompositeAuth;
use yii\helpers\ArrayHelper;
use yii\rest\Controller;
use yii\web\ForbiddenHttpException;

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
        
        if ($success) {
            $user->updateAttributes([
                'auth_tf_enabled' => '1',
                'auth_tf_type' => $choice
            ]);
        }
        
        return [
            'success' => $success,
            'message' => $success ? $object->getSuccessMessage() : $object->getUnsuccessMessage($codeDurationTime)
        ];
    }
}
