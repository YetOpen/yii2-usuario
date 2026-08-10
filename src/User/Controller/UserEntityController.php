<?php

namespace Da\User\Controller;

use Da\User\Helper\UserEntityHelper;
use Da\User\Model\UserEntity;
use Da\User\Model\User;
use Da\User\Repository\UserEntityCredentialSourceRepository;
use Da\User\Traits\ModuleAwareTrait;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorDataLoader;
use Webauthn\CollectedClientData;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Yii;
use yii\helpers\ArrayHelper;
use yii\helpers\Html;
use yii\helpers\Json;
use yii\web\Controller;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;


class UserEntityController extends Controller
{
    use ModuleAwareTrait;
    public $enableCsrfValidation = true;
    public UserEntityHelper $userEntityHelper;


    public function __construct($id, $module, UserEntityHelper $userEntityHelper, $config = [])
    {
        parent::__construct($id, $module, $config);
        $this->userEntityHelper = $userEntityHelper;
    }

    public function actionCreatePasskey(){
        $model = new UserEntity();
        if($this->userEntityHelper->checkAccessConditions()){
            return $this->render('create', ['model' => $model]);
        }
        return $this->goBack();
    }

    /**
     * Issues a fresh, server-generated challenge (and the rest of the creation options) for the
     * registration ceremony. Called via AJAX before navigator.credentials.create().
     */
    public function actionCreatePasskeyChallenge()
    {
        Yii::$app->response->format = Response::FORMAT_JSON;
        if (!$this->userEntityHelper->checkAccessConditions()) {
            throw new ForbiddenHttpException(Yii::t('usuario', 'You are not allowed to perform this action.'));
        }
        return $this->userEntityHelper->challengeGenerationForRegistration();
    }

    //function for updating passkeys, the user can only change the name of it
    public function actionUpdatePasskey($id)
    {
        $model = UserEntity::findOne($id);
        if (!$model || (int) $model->user_id !== (int) Yii::$app->user->id) {
            throw new NotFoundHttpException(Yii::t('usuario', 'Passkey not found.'));
        }

        if (Yii::$app->request->isPost) {
            // Only the "name" is user-editable: assign it directly instead of $model->load(), so a
            // crafted POST body can't reassign credential_id/public_key/user_id/... via mass assignment.
            $model->name = Yii::$app->request->post('UserEntity')['name'] ?? null;
            if ($model->validate(['name']) && $model->save(false, ['name'])) {
                Yii::$app->session->setFlash('success', Yii::t('usuario', 'Passkey updated successfully.'));
                return $this->redirect(['index-passkey']);
            }
            $errors = $model->getFirstErrors();
            $errorMessage = reset($errors) ?: Yii::t('usuario', 'Unable to save changes.');
            Yii::$app->session->setFlash('error', $errorMessage);
        }

        if($this->userEntityHelper->checkAccessConditions()){
            return $this->render('update', [
                'model' => $model,
            ]);
        }
        return $this->goBack();

    }

    public function actionDeletePasskey($id)
    {
        if(!$this->userEntityHelper->checkAccessConditions()){
            return $this->goBack();
        }

        $model = UserEntity::findOne($id);
        if (!$model || (int) $model->user_id !== (int) Yii::$app->user->id) {
            throw new NotFoundHttpException(Yii::t('usuario', 'Passkey not found.'));
        }

        try {
            if ($model->delete() !== false) {
                Yii::$app->session->setFlash('success', Yii::t('usuario', 'Passkey deleted successfully.'));
            } else {
                Yii::$app->session->setFlash('error', Yii::t('usuario', 'Unable to delete the passkey.'));
            }
        } catch (\Exception $e) {
            Yii::error('Passkey deletion error: ' . $e->getMessage(), __METHOD__);
            Yii::$app->session->setFlash('error', Yii::t('usuario', 'Error occurred while deleting the passkey.'));
        }

        return $this->redirect(['index-passkey']);
    }

    public function actionIndexPasskey()
    {
        if(!$this->userEntityHelper->checkAccessConditions()){
            return $this->goBack();
        }
        $dataProvider = $this->userEntityHelper->loadTableData();
        return $this->render('index', [
            'dataProvider' => $dataProvider,
        ]);
    }

    public function actionStorePasskey()
    {
        if (!$this->userEntityHelper->checkAccessConditions()) {
            return $this->goBack();
        }

        $model = new UserEntity();
        $module = $this->getModule();

        if (Yii::$app->request->isPost) {
            $user = Yii::$app->user->identity;

            $existingCount = UserEntity::find()->andWhere(['user_id' => $user->id])->count();
            if ($existingCount >= $module->maxPasskeysForUser) {
                Yii::$app->session->setFlash('error', Yii::t('usuario', 'Maximum number of passkeys reached.'));
                return $this->redirect(['index-passkey']);
            }

            $post = Yii::$app->request->post('UserEntity', []);
            $name = $post['name'] ?? null;
            $credentialIdB64 = $post['credential_id'] ?? null;
            $attestationObjectB64 = $post['public_key'] ?? null;
            $clientDataJsonB64 = $post['client_data_json'] ?? null;

            $challengeBase64 = $this->userEntityHelper->retrieveChallenge();
            // One-shot challenge: consume it now regardless of the outcome below, so a failed/replayed
            // attempt can't be retried against the same challenge.
            $this->userEntityHelper->storeChallenge(null);

            if (!$credentialIdB64 || !$attestationObjectB64 || !$clientDataJsonB64) {
                Yii::$app->session->setFlash('error', Yii::t('usuario', 'Incomplete WebAuthn response.'));
                return $this->render('create', ['model' => $model]);
            }

            if (!$challengeBase64) {
                Yii::$app->session->setFlash('error', Yii::t('usuario', 'Invalid or expired challenge.'));
                return $this->render('create', ['model' => $model]);
            }

            try {
                $clientDataJson = $this->userEntityHelper->base64UrlDecode($clientDataJsonB64);
                $clientDataArray = Json::decode($clientDataJson);
                $collectedClientData = new CollectedClientData($clientDataJson, $clientDataArray);

                $attestationObject = $this->userEntityHelper->createAttestationObjectLoader()->load($attestationObjectB64);
                $attestationResponse = new AuthenticatorAttestationResponse($collectedClientData, $attestationObject, []);

                $rp = new PublicKeyCredentialRpEntity(
                    Yii::$app->name ?: Yii::$app->request->hostName,
                    Yii::$app->request->hostName
                );
                $userEntity = PublicKeyCredentialUserEntity::create($user->username, (string) $user->id, $user->username);
                $creationOptions = new PublicKeyCredentialCreationOptions(
                    $rp,
                    $userEntity,
                    $this->userEntityHelper->base64UrlDecode($challengeBase64),
                    [
                        new PublicKeyCredentialParameters('public-key', -7),
                        new PublicKeyCredentialParameters('public-key', -257),
                    ],
                    null,
                    'none'
                );

                // Full cryptographic verification of the registration ceremony: challenge, origin,
                // rpId hash, attestation statement/signature and algorithm are all checked here.
                $credentialSource = $this->userEntityHelper->createAttestationValidator()->check(
                    $attestationResponse,
                    $creationOptions,
                    Yii::$app->request->hostName
                );
            } catch (\Throwable $e) {
                Yii::error('Passkey registration verification error: ' . $e->getMessage(), __METHOD__);
                Yii::$app->session->setFlash('error', Yii::t('usuario', 'WebAuthn verification failed, the passkey was not registered.'));
                return $this->render('create', ['model' => $model]);
            }

            // Everything persisted below comes from the validated $credentialSource, not from raw
            // client input: the client only supplied opaque blobs that were just cryptographically verified.
            $model->id = (int) ($post['id'] ?? 0);
            $model->user_id = $user->id;
            $model->name = $name;
            $model->type = 'public-key';
            $model->created_at = date('Y-m-d H:i:s');
            $model->credential_id = $this->userEntityHelper->base64UrlEncode($credentialSource->publicKeyCredentialId);
            $model->public_key = $this->userEntityHelper->base64UrlEncode($credentialSource->credentialPublicKey);
            $model->attestation_format = $credentialSource->attestationType ?: 'none';
            $model->sign_count = $credentialSource->counter;
            $model->device_id = Yii::$app->request->userAgent;

            if ($model->validate() && $model->save()) {
                Yii::$app->session->setFlash('success', Yii::t('usuario', 'Passkey registered succesfully.'));
                return $this->redirect(['index-passkey']);
            }

            Yii::error('Error while saving the passkey: ' . json_encode($model->getErrors()));
            Yii::$app->session->setFlash('error', Html::errorSummary($model, [
                'header' => Yii::t('usuario', 'Validation error: '),
            ]));
        }

        return $this->render('create', ['model' => $model]);
    }

    public function actionLoginPasskey()
    {
        $request = Yii::$app->request;
        if ($request->isPost) {
            $body = Json::decode($request->rawBody);
            $credentialIdB64 = ArrayHelper::getValue($body, 'id');
            // if id is missing -> issue a fresh challenge
            if (!$credentialIdB64) {
                return $this->asJson($this->userEntityHelper->challengeGeneration());
            }

            $response = ArrayHelper::getValue($body, 'response', []);
            if (
                empty($response['clientDataJSON']) ||
                empty($response['authenticatorData']) ||
                empty($response['signature'])
            ) {
                return $this->asJson(['success' => false, 'message' => Yii::t('usuario', 'Incomplete WebAuthn response')]);
            }

            $challengeBase64 = $this->userEntityHelper->retrieveChallenge();
            // One-shot challenge: consume it now regardless of the outcome below.
            $this->userEntityHelper->storeChallenge(null);

            if (!$challengeBase64) {
                return $this->asJson(['success' => false, 'message' => Yii::t('usuario', 'Invalid or expired challenge')]);
            }

            $model = UserEntity::findOne(['credential_id' => $credentialIdB64]);
            if (!$model) {
                return $this->asJson(['success' => false, 'message' => Yii::t('usuario', 'Credential not found')]);
            }
            $expectedUserHandle = (string) $model->user_id;

            try {
                $clientDataJson = $this->userEntityHelper->base64UrlDecode($response['clientDataJSON']);
                $clientDataArray = Json::decode($clientDataJson);
                $collectedClientData = new CollectedClientData($clientDataJson, $clientDataArray);

                $authenticatorDataBytes = $this->userEntityHelper->base64UrlDecode($response['authenticatorData']);
                $authenticatorData = AuthenticatorDataLoader::create()->load($authenticatorDataBytes);

                $assertionResponse = new AuthenticatorAssertionResponse(
                    $collectedClientData,
                    $authenticatorData,
                    $this->userEntityHelper->base64UrlDecode($response['signature']),
                    isset($response['userHandle']) ? $this->userEntityHelper->base64UrlDecode($response['userHandle']) : null
                );

                $repository = new UserEntityCredentialSourceRepository();
                $publicKeyCredentialSource = $repository->findOneByCredentialId($credentialIdB64);
                if ($publicKeyCredentialSource === null) {
                    return $this->asJson(['success' => false, 'message' => Yii::t('usuario', 'Credential not found')]);
                }

                $requestOptions = new PublicKeyCredentialRequestOptions(
                    $this->userEntityHelper->base64UrlDecode($challengeBase64),
                    Yii::$app->request->hostName,
                    [],
                    'preferred',
                    60000
                );

                // Full cryptographic verification of the assertion: challenge, origin, rpId hash,
                // signature (proof of possession of the private key) and the anti-clone sign counter.
                $credentialRecord = $this->userEntityHelper->createAssertionValidator()->check(
                    $publicKeyCredentialSource,
                    $assertionResponse,
                    $requestOptions,
                    Yii::$app->request->hostName,
                    $expectedUserHandle
                );

                $user = User::findOne((int) $credentialRecord->userHandle);
                if (!$user) {
                    Yii::error('User not found for handle: ' . $credentialRecord->userHandle, __METHOD__);
                    return $this->asJson(['success' => false, 'message' => Yii::t('usuario', 'User not found')]);
                }
                Yii::$app->user->login($user);

                // Persist the real counter reported by the authenticator (not a manual +1), so future
                // logins can actually detect a cloned authenticator.
                $model->sign_count = $credentialRecord->counter;
                $model->last_used_at = date('Y-m-d H:i:s');
                $model->save(false, ['sign_count', 'last_used_at']);
                return $this->asJson(['success' => true]);

            } catch (\Throwable $e) {
                Yii::error('Login passkey error: ' . $e->getMessage(), __METHOD__);
                // Do not leak $e->getMessage() to the (unauthenticated) caller.
                return $this->asJson([
                    'success' => false,
                    'message' => Yii::t('usuario', 'Verification error of WebAuthn'),
                ]);
            }
        }
        return $this->render('login-passkey');
    }
}
