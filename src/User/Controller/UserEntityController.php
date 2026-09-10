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
use yii\base\InvalidArgumentException;
use yii\filters\AccessControl;
use yii\filters\VerbFilter;
use yii\helpers\ArrayHelper;
use yii\helpers\Html;
use yii\helpers\Json;
use yii\web\Controller;
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

    /**
     * {@inheritdoc}
     */
    public function behaviors()
    {
        return [
            // Side-effectful actions must not be reachable by GET: Yii only checks the CSRF token on
            // non-GET requests, so without this an <img>/<link> tag would delete or mutate a logged-in
            // victim's passkey (their MFA credential) cross-site.
            'verbs' => [
                'class' => VerbFilter::class,
                'actions' => [
                    'delete-passkey' => ['post'],
                    'store-passkey' => ['post'],
                    'create-passkey-challenge' => ['post'],
                    'update-passkey' => ['get', 'post'],
                    'login-passkey' => ['get', 'post'],
                ],
            ],
            'access' => [
                'class' => AccessControl::class,
                'rules' => [
                    // The login ceremony is the only action an anonymous user may reach.
                    [
                        'allow' => true,
                        'actions' => ['login-passkey'],
                        'roles' => ['?', '@'],
                    ],
                    // Everything else is passkey management and requires an authenticated user.
                    [
                        'allow' => true,
                        'roles' => ['@'],
                    ],
                ],
            ],
        ];
    }

    /**
     * The whole controller is inert unless passkey login is enabled. This makes `enablePasskeyLogin`
     * a real kill switch (disabling it revokes passkey access, including the login ceremony), instead
     * of a flag that only hides the button on the login form.
     *
     * {@inheritdoc}
     */
    public function beforeAction($action)
    {
        if (!parent::beforeAction($action)) {
            return false;
        }
        if (!$this->getModule()->enablePasskeyLogin) {
            throw new NotFoundHttpException();
        }
        return true;
    }

    public function actionCreatePasskey()
    {
        return $this->render('create', ['model' => new UserEntity()]);
    }

    /**
     * Issues a fresh, server-generated challenge (and the rest of the creation options) for the
     * registration ceremony. Called via AJAX before navigator.credentials.create().
     */
    public function actionCreatePasskeyChallenge()
    {
        Yii::$app->response->format = Response::FORMAT_JSON;
        return $this->userEntityHelper->challengeGenerationForRegistration();
    }

    /**
     * Updating a passkey: the user can only change its name.
     */
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
            Yii::$app->session->setFlash('error', reset($errors) ?: Yii::t('usuario', 'Unable to save changes.'));
        }

        return $this->render('update', ['model' => $model]);
    }

    public function actionDeletePasskey($id)
    {
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
        return $this->render('index', [
            'dataProvider' => $this->userEntityHelper->loadTableData(),
        ]);
    }

    public function actionStorePasskey()
    {
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

            $challengeBase64 = $this->userEntityHelper->retrieveChallenge('registration');
            // One-shot challenge: consume it now regardless of the outcome below, so a failed/replayed
            // attempt can't be retried against the same challenge.
            $this->userEntityHelper->storeChallenge(null, 'registration');

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
                $collectedClientData = new CollectedClientData($clientDataJson, Json::decode($clientDataJson));

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
            // client input: the client only supplied opaque blobs that were just cryptographically
            // verified. The primary key is left to the database auto-increment.
            $model->user_id = $user->id;
            $model->name = $name;
            $model->type = 'public-key';
            $model->created_at = time();
            $model->credential_id = $this->userEntityHelper->base64UrlEncode($credentialSource->publicKeyCredentialId);
            $model->public_key = $this->userEntityHelper->base64UrlEncode($credentialSource->credentialPublicKey);
            $model->attestation_type = $credentialSource->attestationType ?: 'none';
            $model->sign_count = $credentialSource->counter;
            // The user agent is not a stable identifier and can be long; keep it only as a hint and
            // never let its length fail validation after a successful ceremony.
            $model->device_id = mb_substr((string) Yii::$app->request->userAgent, 0, 512);

            if ($model->validate() && $model->save()) {
                Yii::$app->session->setFlash('success', Yii::t('usuario', 'Passkey registered successfully.'));
                return $this->redirect(['index-passkey']);
            }

            Yii::error('Error while saving the passkey: ' . Json::encode($model->getErrors()), __METHOD__);
            Yii::$app->session->setFlash('error', Html::errorSummary($model, [
                'header' => Yii::t('usuario', 'Validation error: '),
            ]));
        }

        return $this->render('create', ['model' => $model]);
    }

    public function actionLoginPasskey()
    {
        $request = Yii::$app->request;

        if (!$request->isPost) {
            // The button is a real link/button; a plain GET (middle-click, new tab, bookmark, a
            // crawler, or an earlier JS error on the page) must not 500 on a missing view.
            return $this->redirect(['/user/security/login']);
        }

        try {
            $body = Json::decode($request->rawBody);
        } catch (InvalidArgumentException $e) {
            return $this->asJson(['success' => false, 'message' => Yii::t('usuario', 'Initial data isn\'t valid')]);
        }

        $credentialIdB64 = ArrayHelper::getValue($body, 'id');
        // No credential id in the body -> this is the first leg: issue a fresh challenge.
        if (!$credentialIdB64) {
            return $this->asJson($this->userEntityHelper->challengeGeneration());
        }

        $response = ArrayHelper::getValue($body, 'response', []);
        if (empty($response['clientDataJSON']) || empty($response['authenticatorData']) || empty($response['signature'])) {
            return $this->asJson(['success' => false, 'message' => Yii::t('usuario', 'Incomplete WebAuthn response')]);
        }

        $challengeBase64 = $this->userEntityHelper->retrieveChallenge('login');
        // One-shot challenge: consume it now regardless of the outcome below.
        $this->userEntityHelper->storeChallenge(null, 'login');
        if (!$challengeBase64) {
            return $this->asJson(['success' => false, 'message' => Yii::t('usuario', 'Invalid or expired challenge')]);
        }

        $module = $this->getModule();

        try {
            $repository = new UserEntityCredentialSourceRepository();
            $publicKeyCredentialSource = $repository->findOneByCredentialId($credentialIdB64);
            $model = $repository->getModel();
            if ($publicKeyCredentialSource === null || $model === null) {
                return $this->asJson(['success' => false, 'message' => Yii::t('usuario', 'Credential not found')]);
            }

            $clientDataJson = $this->userEntityHelper->base64UrlDecode($response['clientDataJSON']);
            $collectedClientData = new CollectedClientData($clientDataJson, Json::decode($clientDataJson));

            $authenticatorData = AuthenticatorDataLoader::create()
                ->load($this->userEntityHelper->base64UrlDecode($response['authenticatorData']));

            $assertionResponse = new AuthenticatorAssertionResponse(
                $collectedClientData,
                $authenticatorData,
                $this->userEntityHelper->base64UrlDecode($response['signature']),
                isset($response['userHandle']) ? $this->userEntityHelper->base64UrlDecode($response['userHandle']) : null
            );

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
                (string) $model->user_id
            );

            $user = User::findOne((int) $credentialRecord->userHandle);
            if (!$user) {
                Yii::error('User not found for handle: ' . $credentialRecord->userHandle, __METHOD__);
                return $this->asJson(['success' => false, 'message' => Yii::t('usuario', 'User not found')]);
            }

            // A valid assertion alone is not enough: apply the same account-state gates that
            // Da\User\Form\LoginForm enforces for a password login.
            if ($user->getIsBlocked()) {
                return $this->asJson(['success' => false, 'message' => Yii::t('usuario', 'Your account has been blocked')]);
            }
            if ($module->enableEmailConfirmation && !$module->allowUnconfirmedEmailLogin && !$user->getIsConfirmed()) {
                return $this->asJson(['success' => false, 'message' => Yii::t('usuario', 'You need to confirm your email address')]);
            }
            if ($module->passkeyLoginRequiresTwoFactor && $user->auth_tf_enabled) {
                return $this->asJson([
                    'success' => false,
                    'message' => Yii::t('usuario', 'Please sign in with your password to complete two-factor authentication.'),
                ]);
            }

            // Persist the real counter reported by the authenticator (not a manual +1) and the last
            // usage BEFORE the session is established, so a failed write is not masked by an
            // already-logged-in state and clone detection keeps working.
            $model->sign_count = $credentialRecord->counter;
            $model->last_used_at = time();
            if (!$model->save(false, ['sign_count', 'last_used_at'])) {
                Yii::error('Could not persist passkey counter: ' . Json::encode($model->getErrors()), __METHOD__);
            }

            Yii::$app->user->login($user);

            $user->updateAttributes([
                'last_login_at' => time(),
                'last_login_ip' => $module->disableIpLogging ? '127.0.0.1' : Yii::$app->request->getUserIP(),
            ]);

            return $this->asJson(['success' => true]);
        } catch (\Throwable $e) {
            Yii::error('Login passkey error: ' . $e->getMessage(), __METHOD__);
            // Do not leak $e->getMessage() to the (unauthenticated) caller.
            return $this->asJson(['success' => false, 'message' => Yii::t('usuario', 'Verification error of WebAuthn')]);
        }
    }
}
