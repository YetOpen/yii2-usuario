<?php

/*
 * This file is part of the 2amigos/yii2-usuario project.
 *
 * (c) 2amigOS! <http://2amigos.us/>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Da\User\Controller;

use Da\User\Contracts\AuthClientInterface;
use Da\User\Event\FormEvent;
use Da\User\Event\UserEvent;
use Da\User\Factory\MailFactory;
use Da\User\Form\LoginForm;
use Da\User\Model\AuthTfRecoveryCode;
use Da\User\Model\User;
use Da\User\Query\SocialNetworkAccountQuery;
use Da\User\Service\SocialNetworkAccountConnectService;
use Da\User\Service\SocialNetworkAuthenticateService;
use Da\User\Service\TwoFactorDisableService;
use Da\User\Traits\ContainerAwareTrait;
use Da\User\Traits\ModuleAwareTrait;
use Yii;
use yii\authclient\AuthAction;
use yii\base\InvalidConfigException;
use yii\base\InvalidParamException;
use yii\base\Module;
use yii\filters\AccessControl;
use yii\filters\VerbFilter;
use yii\helpers\ArrayHelper;
use yii\web\Controller;
use yii\web\Response;
use yii\widgets\ActiveForm;

class SecurityController extends Controller
{
    use ContainerAwareTrait;
    use ModuleAwareTrait;

    protected $socialNetworkAccountQuery;

    /**
     * SecurityController constructor.
     *
     * @param string                    $id
     * @param Module                    $module
     * @param SocialNetworkAccountQuery $socialNetworkAccountQuery
     * @param array                     $config
     */
    public function __construct(
        $id,
        Module $module,
        SocialNetworkAccountQuery $socialNetworkAccountQuery,
        array $config = []
    ) {
        $this->socialNetworkAccountQuery = $socialNetworkAccountQuery;
        parent::__construct($id, $module, $config);
    }

    /**
     * {@inheritdoc}
     */
    public function behaviors()
    {
        return [
            'access' => [
                'class' => AccessControl::class,
                'rules' => [
                    [
                        'allow' => true,
                        'actions' => ['login', 'confirm', 'recovery-code', 'auth'],
                        'roles' => ['?'],
                    ],
                    [
                        'allow' => true,
                        'actions' => ['login', 'auth', 'logout'],
                        'roles' => ['@'],
                    ],
                ],
            ],
            'verbs' => [
                'class' => VerbFilter::class,
                'actions' => [
                    'logout' => ['post'],
                ],
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function actions()
    {
        return [
            'auth' => [
                'class' => AuthAction::class,
                // if user is not logged in, will try to log him in, otherwise
                // will try to connect social account to user.
                'successCallback' => Yii::$app->user->isGuest
                    ? [$this, 'authenticate']
                    : [$this, 'connect'],
            ],
        ];
    }

    /**
     * Controller action responsible for handling login page and actions.
     *
     * @throws InvalidConfigException
     * @throws InvalidParamException
     * @return array|string|Response
     */
    public function actionLogin()
    {
        if (!Yii::$app->user->getIsGuest()) {
            return $this->goHome();
        }

        /**
        * @var LoginForm $form
        */
        $form = $this->make(LoginForm::class);

        /**
        * @var FormEvent $event
        */
        $event = $this->make(FormEvent::class, [$form]);

        if (Yii::$app->request->isAjax && $form->load(Yii::$app->request->post())) {
            Yii::$app->response->format = Response::FORMAT_JSON;

            $errors = ActiveForm::validate($form);
            if (empty($errors)) {
                return $errors;
            }
            $this->trigger(FormEvent::EVENT_FAILED_LOGIN, $event);
            return $errors;
        }

        if ($form->load(Yii::$app->request->post())) {
            if ($this->module->enableTwoFactorAuthentication && $form->validate()) {
                $user = $form->getUser();

                if ($user->auth_tf_enabled) {
                    Yii::$app->session->set('credentials', ['login' => $form->login, 'pwd' => $form->password]);
                    return $this->redirect(['confirm']);
                }
            }

            $this->trigger(FormEvent::EVENT_BEFORE_LOGIN, $event);
            if ($form->login()) {
                $form->getUser()->updateAttributes([
                    'last_login_at' => time(),
                    'last_login_ip' => $this->module->disableIpLogging ? '127.0.0.1' : Yii::$app->request->getUserIP(),
                ]);

                $this->trigger(FormEvent::EVENT_AFTER_LOGIN, $event);

                return $this->goBack();
            }
            $this->trigger(FormEvent::EVENT_FAILED_LOGIN, $event);
        }

        return $this->render(
            'login',
            [
                'model' => $form,
                'module' => $this->module,
            ]
        );
    }

    public function actionConfirm()
    {
        if (!Yii::$app->user->getIsGuest()) {
            return $this->goHome();
        }

        if (!Yii::$app->session->has('credentials')) {
            return $this->redirect(['login']);
        }

        $credentials = Yii::$app->session->get('credentials');
        /**
        * @var LoginForm $form
        */
        $form = $this->make(LoginForm::class);
        $form->login = $credentials['login'];
        $form->password = $credentials['pwd'];
        $form->setScenario('2fa');

        /**
        * @var FormEvent $event
        */
        $event = $this->make(FormEvent::class, [$form]);

        if (Yii::$app->request->isAjax && $form->load(Yii::$app->request->post())) {
            Yii::$app->response->format = Response::FORMAT_JSON;

            return ActiveForm::validate($form);
        }

        if ($form->load(Yii::$app->request->post())) {
            $this->trigger(FormEvent::EVENT_BEFORE_LOGIN, $event);

            if ($form->login()) {
                Yii::$app->session->set('credentials', null);

                $form->getUser()->updateAttributes(['last_login_at' => time()]);

                $this->trigger(FormEvent::EVENT_AFTER_LOGIN, $event);

                return $this->goBack();
            }
        } else {
            $module = Yii::$app->getModule('user');
            $validators = $module->twoFactorAuthenticationValidators;
            $credentials = Yii::$app->session->get('credentials');
            $login = $credentials['login'];
            $userModel = $this->getClassMap()->get(User::class);
            $user = $userModel::findOne(['email' => $login]);
            if ($user == null) {
                $user = $userModel::findOne(['username' => $login]);
            }
            $tfType = $user->getAuthTfType();

            $class = ArrayHelper::getValue($validators, $tfType.'.class');
            $object = $this
                ->make($class, [$user, null, $this->module->twoFactorAuthenticationCycles]);

            $object->generateCode();
        }

        return $this->render(
            'confirm',
            [
                'model' => $form,
                'module' => $this->module
            ]
        );
    }

    /**
     * Uses a recovery code to turn two-factor authentication off — the escape hatch for
     * when the user's normal second factor is no longer reachable (e.g. a lost or broken
     * phone). Mirrors {@see \Da\User\Controller\api\v1\SecurityController::actionRecoveryCodeVerify()}
     * for the session-based web login: it does NOT log the user in, it only disables 2FA
     * (via {@see TwoFactorDisableService}) and sends them back to the login form, since the
     * credentials they already gave in {@see actionLogin()} are still valid and will now
     * succeed without a 2FA challenge.
     */
    public function actionRecoveryCode()
    {
        if (!Yii::$app->user->getIsGuest()) {
            return $this->goHome();
        }

        if (!Yii::$app->session->has('credentials')) {
            return $this->redirect(['login']);
        }

        $credentials = Yii::$app->session->get('credentials');
        $userModel = $this->getClassMap()->get(User::class);
        $user = $userModel::findOne(['email' => $credentials['login']]);
        if ($user === null) {
            $user = $userModel::findOne(['username' => $credentials['login']]);
        }

        if ($user === null || !$user->auth_tf_enabled) {
            return $this->redirect(['login']);
        }

        if (Yii::$app->request->isPost) {
            $recoveryCode = trim((string) Yii::$app->request->post('recoveryCode'));

            if ($recoveryCode === '') {
                Yii::$app
                    ->getSession()
                    ->setFlash('danger', Yii::t('usuario', 'Please enter a recovery code.'));
            } else {
                // Codes are hashed (see RecoveryCodeGeneratorService), so a matching one can
                // only be found by checking the submitted value against each stored hash in
                // turn, not by a direct lookup.
                $matchedCode = null;
                foreach (AuthTfRecoveryCode::find()->whereUserId($user->id)->whereUnused()->all() as $candidate) {
                    if (Yii::$app->security->validatePassword($recoveryCode, $candidate->code_hash)) {
                        $matchedCode = $candidate;
                        break;
                    }
                }

                if ($matchedCode !== null) {
                    $this->make(TwoFactorDisableService::class, [$user])->run();

                    // Best-effort: the only out-of-band signal that lets the legitimate user
                    // notice and react (re-enable 2FA, contact support) if they weren't the one
                    // who did this, but a mailer failure must not undo the disable that already
                    // succeeded.
                    try {
                        MailFactory::makeTwoFactorDisabledMailerService($user)->run();
                    } catch (\Throwable $e) {
                        Yii::error("Failed to send 2FA-disabled notification to user {$user->id}: {$e->getMessage()}", __METHOD__);
                    }

                    Yii::$app->session->set('credentials', null);
                    Yii::$app
                        ->getSession()
                        ->setFlash(
                            'success',
                            Yii::t('usuario', 'Two factor authentication has been disabled. Please log in again.')
                        );

                    return $this->redirect(['login']);
                }

                Yii::$app
                    ->getSession()
                    ->setFlash('danger', Yii::t('usuario', 'Invalid or already used recovery code.'));
            }
        }

        return $this->render(
            'recovery-code',
            [
                'module' => $this->module,
            ]
        );
    }

    public function actionLogout()
    {
        $event = $this->make(UserEvent::class, [Yii::$app->getUser()->getIdentity()]);

        $this->trigger(UserEvent::EVENT_BEFORE_LOGOUT, $event);

        if (Yii::$app->getUser()->logout()) {
            $this->trigger(UserEvent::EVENT_AFTER_LOGOUT, $event);
        }

        return $this->goHome();
    }

    public function authenticate(AuthClientInterface $client)
    {
        $this->make(SocialNetworkAuthenticateService::class, [$this, $this->action, $client])->run();
    }

    public function connect(AuthClientInterface $client)
    {
        if (Yii::$app->user->isGuest) {
            Yii::$app->session->setFlash('danger', Yii::t('usuario', 'Something went wrong'));

            return;
        }

        $this->make(SocialNetworkAccountConnectService::class, [$this, $client])->run();
    }
}
